package io.floci.az.services.keyvault;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * BYOK import: a {@code key_hsm} transfer blob built the way an HSM vendor's BYOK tool builds it
 * (RSA-OAEP SHA-1 over an ephemeral AES key, then AES Key Wrap with Padding over the target key).
 */
@QuarkusTest
class KeyVaultByokTest {

    private static final String VAULT = "/devstoreaccount1-keyvault";
    private static final String HSM = "/devstoreaccount1-managedhsm";
    private static final String API = "?api-version=7.6";
    private static final String AUTH = "Bearer fake";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    @BeforeEach
    void reset() {
        given().post("/_admin/reset").then().statusCode(204);
    }

    @Test
    void importsAnRsaKeyThatDecryptsWhatItsPublicKeyEncrypted() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        KeyPair target = generate("RSA", 2048);
        String body = importBody("RSA-HSM", null, "[\"encrypt\",\"decrypt\"]",
                blob(kek, target.getPrivate().getEncoded()));

        given().header("Authorization", AUTH).contentType(ContentType.JSON).body(body)
                .when().put(VAULT + "/keys/byok-rsa" + API)
                .then().statusCode(200)
                .body("key.kty", equalTo("RSA-HSM"))
                .body("key.n", equalTo(unsigned(((RSAPublicKey) target.getPublic()).getModulus())))
                .body("key.key_ops", contains("encrypt", "decrypt"))
                .body("key.d", nullValue())
                .body("key.key_hsm", nullValue());

        byte[] secret = "imported through BYOK".getBytes(StandardCharsets.UTF_8);
        Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        oaep.init(Cipher.ENCRYPT_MODE, target.getPublic());
        given().header("Authorization", AUTH).contentType(ContentType.JSON)
                .body("{\"alg\":\"RSA-OAEP\",\"value\":\"" + URL.encodeToString(oaep.doFinal(secret)) + "\"}")
                .when().post(VAULT + "/keys/byok-rsa/decrypt" + API)
                .then().statusCode(200)
                .body("value", equalTo(URL.encodeToString(secret)));
    }

    @Test
    void importsEcKeysAndDerivesTheirPublicPoint() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        for (String[] curve : new String[][] {{"P-256", "secp256r1", "32"}, {"P-521", "secp521r1", "66"}}) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve[1]));
            KeyPair target = generator.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) target.getPublic();
            int length = Integer.parseInt(curve[2]);

            given().header("Authorization", AUTH).contentType(ContentType.JSON)
                    .body(importBody("EC-HSM", curve[0], "[\"sign\",\"verify\"]",
                            blob(kek, target.getPrivate().getEncoded())))
                    .when().put(VAULT + "/keys/byok-" + curve[0] + API)
                    .then().statusCode(200)
                    .body("key.kty", equalTo("EC-HSM"))
                    .body("key.crv", equalTo(curve[0]))
                    .body("key.x", equalTo(fixed(pub.getW().getAffineX(), length)))
                    .body("key.y", equalTo(fixed(pub.getW().getAffineY(), length)))
                    .body("key.d", nullValue());
        }
    }

    @Test
    void importsAnAesKeyIntoAManagedHsm() throws Exception {
        Kek kek = createKek(HSM, "kek");
        byte[] aes = new byte[32];
        RANDOM.nextBytes(aes);

        given().header("Authorization", AUTH).contentType(ContentType.JSON)
                .body(importBody("oct-HSM", null, "[\"encrypt\",\"decrypt\"]", blob(kek, aes)))
                .when().put(HSM + "/keys/byok-aes" + API)
                .then().statusCode(200)
                .body("key.kty", equalTo("oct-HSM"))
                .body("key.key_size", equalTo(256))
                .body("key.k", nullValue())
                .body("key.kid", containsString(".managedhsm.azure.net/keys/byok-aes/"));

        byte[] plaintext = "aes through byok".getBytes(StandardCharsets.UTF_8);
        Response encrypted = given().header("Authorization", AUTH).contentType(ContentType.JSON)
                .body("{\"alg\":\"A256GCM\",\"value\":\"" + URL.encodeToString(plaintext) + "\"}")
                .when().post(HSM + "/keys/byok-aes/encrypt" + API);
        encrypted.then().statusCode(200);

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes, "AES"),
                new GCMParameterSpec(128, URL_DECODER.decode(encrypted.jsonPath().getString("iv"))));
        byte[] ciphertext = URL_DECODER.decode(encrypted.jsonPath().getString("value"));
        byte[] tag = URL_DECODER.decode(encrypted.jsonPath().getString("tag"));
        gcm.update(ciphertext);
        assertArrayEquals(plaintext, gcm.doFinal(tag));
    }

    @Test
    void acceptsAStandardBase64TransferBlob() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        KeyPair target = generate("RSA", 2048);
        String urlBlob = blob(kek, target.getPrivate().getEncoded());
        String standardBlob = Base64.getEncoder().encodeToString(URL_DECODER.decode(urlBlob));

        given().header("Authorization", AUTH).contentType(ContentType.JSON)
                .body(importBody("RSA-HSM", null, null, standardBlob))
                .when().put(VAULT + "/keys/byok-std" + API)
                .then().statusCode(200)
                .body("key.kty", equalTo("RSA-HSM"));
    }

    @Test
    void anAesKeyCannotBeImportedIntoAVault() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        badRequest(VAULT, importBody("oct-HSM", null, null, blob(kek, new byte[32])), "Managed HSM");
    }

    @Test
    void aSoftwareKeyTypeIsRejected() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        badRequest(VAULT, importBody("RSA", null, null, blob(kek, generate("RSA", 2048).getPrivate().getEncoded())),
                "RSA-HSM, EC-HSM or oct-HSM");
    }

    @Test
    void theKeyExchangeKeyMustAllowImport() throws Exception {
        Kek kek = createKey(VAULT, "kek", "[\"encrypt\",\"decrypt\"]");
        badRequest(VAULT, importBody("RSA-HSM", null, null, blob(kek, generate("RSA", 2048).getPrivate().getEncoded())),
                "import operation");
    }

    @Test
    void theKeyExchangeKeyMustBeInThisVault() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        Kek elsewhere = new Kek(kek.kid().replace("devstoreaccount1.vault", "other.vault"), kek.publicKey());
        keyNotFound(VAULT, importBody("RSA-HSM", null, null,
                blob(elsewhere, generate("RSA", 2048).getPrivate().getEncoded())), elsewhere.kid());

        Kek missing = new Kek(kek.kid().replace("/keys/kek/", "/keys/nokek/"), kek.publicKey());
        keyNotFound(VAULT, importBody("RSA-HSM", null, null,
                blob(missing, generate("RSA", 2048).getPrivate().getEncoded())), missing.kid());
    }

    @Test
    void aBlobWrappedForAnotherKeyExchangeKeyIsRejected() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        Kek other = createKek(VAULT, "other");
        Kek mismatched = new Kek(kek.kid(), other.publicKey());
        badRequest(VAULT, importBody("RSA-HSM", null, null,
                blob(mismatched, generate("RSA", 2048).getPrivate().getEncoded())), "could not be decrypted");
    }

    @Test
    void anUnsupportedEncIsRejected() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        String blob = URL.encodeToString(("{\"schema_version\":\"1.0.0\",\"header\":{\"kid\":\"" + kek.kid()
                + "\",\"alg\":\"dir\",\"enc\":\"CKM_AES_KEY_WRAP\"},\"ciphertext\":\"AAAA\"}")
                .getBytes(StandardCharsets.UTF_8));
        badRequest(VAULT, importBody("RSA-HSM", null, null, blob), "enc");
    }

    @Test
    void anEcKeyOnAnotherCurveThanRequestedIsRejected() throws Exception {
        Kek kek = createKek(VAULT, "kek");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        badRequest(VAULT, importBody("EC-HSM", "P-256", null,
                blob(kek, generator.generateKeyPair().getPrivate().getEncoded())), "does not match");
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private record Kek(String kid, PublicKey publicKey) {}

    private static Kek createKek(String base, String name) throws Exception {
        return createKey(base, name, "[\"import\"]");
    }

    private static Kek createKey(String base, String name, String keyOps) throws Exception {
        Response created = given().header("Authorization", AUTH).contentType(ContentType.JSON)
                .body("{\"kty\":\"RSA-HSM\",\"key_size\":2048,\"key_ops\":" + keyOps + "}")
                .when().post(base + "/keys/" + name + "/create" + API);
        created.then().statusCode(200);
        BigInteger n = new BigInteger(1, URL_DECODER.decode(created.jsonPath().getString("key.n")));
        BigInteger e = new BigInteger(1, URL_DECODER.decode(created.jsonPath().getString("key.e")));
        PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        return new Kek(created.jsonPath().getString("key.kid"), pub);
    }

    private static String blob(Kek kek, byte[] targetKey) throws Exception {
        byte[] aes = new byte[32];
        RANDOM.nextBytes(aes);
        Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        oaep.init(Cipher.ENCRYPT_MODE, kek.publicKey());
        byte[] wrappedAes = oaep.doFinal(aes);
        Cipher kwp = Cipher.getInstance("AES/KWP/NoPadding");
        kwp.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"));
        byte[] wrappedTarget = kwp.doFinal(targetKey);
        byte[] ciphertext = new byte[wrappedAes.length + wrappedTarget.length];
        System.arraycopy(wrappedAes, 0, ciphertext, 0, wrappedAes.length);
        System.arraycopy(wrappedTarget, 0, ciphertext, wrappedAes.length, wrappedTarget.length);
        String json = "{\"schema_version\":\"1.0.0\",\"header\":{\"kid\":\"" + kek.kid()
                + "\",\"alg\":\"dir\",\"enc\":\"CKM_RSA_AES_KEY_WRAP\"},\"ciphertext\":\""
                + URL.encodeToString(ciphertext) + "\",\"generator\":\"floci-az tests\"}";
        return URL.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String importBody(String kty, String crv, String keyOps, String keyHsm) {
        return "{\"key\":{\"kty\":\"" + kty + "\""
                + (crv != null ? ",\"crv\":\"" + crv + "\"" : "")
                + (keyOps != null ? ",\"key_ops\":" + keyOps : "")
                + ",\"key_hsm\":\"" + keyHsm + "\"},\"attributes\":{\"enabled\":true}}";
    }

    private static void badRequest(String base, String body, String messagePart) {
        rejected(base, body, 400, "BadParameter", messagePart);
    }

    private static void keyNotFound(String base, String body, String kid) {
        rejected(base, body, 404, "KeyNotFound", kid);
    }

    private static void rejected(String base, String body, int status, String code, String messagePart) {
        given().header("Authorization", AUTH).contentType(ContentType.JSON).body(body)
                .when().put(base + "/keys/rejected" + API)
                .then().statusCode(status)
                .body("error.code", equalTo(code))
                .body("error.message", containsString(messagePart));
        given().header("Authorization", AUTH)
                .when().get(base + "/keys/rejected" + API)
                .then().statusCode(404);
    }

    private static KeyPair generate(String algorithm, int size) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(size);
        return generator.generateKeyPair();
    }

    private static String unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return URL.encodeToString(bytes);
    }

    private static String fixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return URL.encodeToString(out);
    }
}
