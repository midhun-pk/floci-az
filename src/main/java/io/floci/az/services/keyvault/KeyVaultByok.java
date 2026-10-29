package io.floci.az.services.keyvault;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bring-your-own-key import: unwraps the {@code key_hsm} transfer blob described in the Azure Key Vault
 * BYOK specification. The blob's ciphertext is {@code CKM_RSA_AES_KEY_WRAP}: an ephemeral AES key
 * encrypted with the key exchange key (RSA-OAEP, SHA-1), followed by the target key encrypted with that
 * AES key (AES Key Wrap with Padding, RFC 5649). The target key is PKCS#8 for RSA and EC, raw bytes for oct.
 */
final class KeyVaultByok {

    static final String ENC_RSA_AES_KEY_WRAP = "CKM_RSA_AES_KEY_WRAP";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String OAEP_SHA1 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String AES_KWP = "AES/KWP/NoPadding";

    private KeyVaultByok() {
    }

    /** The parts of a transfer blob the import needs: which key exchange key protects it, and the ciphertext. */
    record TransferBlob(String kid, byte[] ciphertext) {}

    static TransferBlob parseTransferBlob(String keyHsm) {
        Map<String, Object> blob;
        try {
            blob = MAPPER.readValue(decodeBase64(keyHsm), new TypeReference<>() {});
        } catch (IOException e) {
            throw new KeyVaultCrypto.CryptoException("key_hsm is not a valid key transfer blob", e);
        }
        if (!(blob.get("header") instanceof Map<?, ?> header)) {
            throw new KeyVaultCrypto.CryptoException("The key transfer blob has no header");
        }
        if (!(header.get("kid") instanceof String kid) || kid.isBlank()) {
            throw new KeyVaultCrypto.CryptoException("The key transfer blob header has no kid");
        }
        if (!"dir".equals(header.get("alg"))) {
            throw new KeyVaultCrypto.CryptoException("Unsupported key transfer blob alg: " + header.get("alg"));
        }
        if (!ENC_RSA_AES_KEY_WRAP.equals(header.get("enc"))) {
            throw new KeyVaultCrypto.CryptoException("Unsupported key transfer blob enc: " + header.get("enc"));
        }
        if (!(blob.get("ciphertext") instanceof String ciphertext) || ciphertext.isBlank()) {
            throw new KeyVaultCrypto.CryptoException("The key transfer blob has no ciphertext");
        }
        return new TransferBlob(kid, decodeBase64(ciphertext));
    }

    /** Recovers the target key's plaintext encoding with the key exchange key's private half. */
    static byte[] unwrap(Map<String, Object> kekJwk, byte[] ciphertext) {
        PrivateKey kek = KeyVaultCrypto.reconstructRsaPrivate(kekJwk);
        int modulusLength = KeyVaultCrypto.b64UrlDecode((String) kekJwk.get("n")).length;
        if (ciphertext.length <= modulusLength) {
            throw new KeyVaultCrypto.CryptoException("The key transfer blob ciphertext is too short");
        }
        try {
            Cipher rsa = Cipher.getInstance(OAEP_SHA1);
            rsa.init(Cipher.DECRYPT_MODE, kek);
            byte[] aesKey = rsa.doFinal(Arrays.copyOfRange(ciphertext, 0, modulusLength));
            if (aesKey.length != 16 && aesKey.length != 24 && aesKey.length != 32) {
                throw new KeyVaultCrypto.CryptoException("The key transfer blob carries an invalid AES key");
            }
            Cipher kwp = Cipher.getInstance(AES_KWP);
            kwp.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
            return kwp.doFinal(Arrays.copyOfRange(ciphertext, modulusLength, ciphertext.length));
        } catch (KeyVaultCrypto.CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyVaultCrypto.CryptoException(
                    "The key transfer blob could not be decrypted with the key exchange key", e);
        }
    }

    /**
     * Builds the stored JWK for an unwrapped target key. {@code crv} is the curve the request names for an
     * EC key, or null to take the key's own.
     */
    static Map<String, Object> targetJwk(String kty, String crv, List<String> keyOps, byte[] plaintext) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", kty);
        jwk.put("key_ops", keyOps);
        switch (KeyVaultCrypto.baseKty(kty)) {
            case "RSA" -> putRsa(jwk, plaintext);
            case "EC" -> putEc(jwk, crv, plaintext);
            case "oct" -> {
                int bits = plaintext.length * 8;
                if (bits != 128 && bits != 192 && bits != 256) {
                    throw new KeyVaultCrypto.CryptoException("Unsupported oct key size: " + bits);
                }
                jwk.put("k", KeyVaultCrypto.b64Url(plaintext));
                jwk.put("keySize", bits);
            }
            default -> throw new KeyVaultCrypto.CryptoException("Unsupported key type: " + kty);
        }
        return jwk;
    }

    private static void putRsa(Map<String, Object> jwk, byte[] pkcs8) {
        RSAPrivateCrtKey key;
        try {
            if (!(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8))
                    instanceof RSAPrivateCrtKey crt)) {
                throw new KeyVaultCrypto.CryptoException("The RSA target key has no CRT parameters");
            }
            key = crt;
        } catch (KeyVaultCrypto.CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyVaultCrypto.CryptoException("The target key is not a PKCS#8 RSA private key", e);
        }
        jwk.put("n", unsigned(key.getModulus()));
        jwk.put("e", unsigned(key.getPublicExponent()));
        jwk.put("d", unsigned(key.getPrivateExponent()));
        jwk.put("p", unsigned(key.getPrimeP()));
        jwk.put("q", unsigned(key.getPrimeQ()));
        jwk.put("dp", unsigned(key.getPrimeExponentP()));
        jwk.put("dq", unsigned(key.getPrimeExponentQ()));
        jwk.put("qi", unsigned(key.getCrtCoefficient()));
        jwk.put("keySize", key.getModulus().bitLength());
    }

    private static void putEc(Map<String, Object> jwk, String requestedCrv, byte[] pkcs8) {
        ECPrivateKey key;
        try {
            key = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (Exception e) {
            throw new KeyVaultCrypto.CryptoException("The target key is not a PKCS#8 EC private key", e);
        }
        String crv = curveName(key.getParams());
        if (requestedCrv != null && !requestedCrv.equals(crv)) {
            throw new KeyVaultCrypto.CryptoException(
                    "The target key's curve " + crv + " does not match the requested curve " + requestedCrv);
        }
        ECParameterSpec params = KeyVaultCrypto.ecParams(crv);
        int fieldLength = (params.getCurve().getField().getFieldSize() + 7) / 8;
        ECPoint w = multiply(params, key.getS());
        jwk.put("crv", crv);
        jwk.put("x", KeyVaultCrypto.b64Url(KeyVaultCrypto.fixedLengthUnsigned(w.getAffineX(), fieldLength)));
        jwk.put("y", KeyVaultCrypto.b64Url(KeyVaultCrypto.fixedLengthUnsigned(w.getAffineY(), fieldLength)));
        jwk.put("d", KeyVaultCrypto.b64Url(KeyVaultCrypto.fixedLengthUnsigned(key.getS(), fieldLength)));
    }

    private static String curveName(ECParameterSpec keyParams) {
        for (String crv : List.of("P-256", "P-384", "P-521")) {
            ECParameterSpec candidate = KeyVaultCrypto.ecParams(crv);
            if (candidate.getCurve().equals(keyParams.getCurve())
                    && candidate.getGenerator().equals(keyParams.getGenerator())) {
                return crv;
            }
        }
        throw new KeyVaultCrypto.CryptoException("The EC target key uses an unsupported curve");
    }

    /**
     * The public point {@code s·G}. The JDK exposes no point arithmetic, and a PKCS#8 EC key need not carry
     * its public point, so it is derived here with affine double-and-add over the prime field.
     */
    static ECPoint multiply(ECParameterSpec params, BigInteger scalar) {
        EllipticCurve curve = params.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger a = curve.getA();
        ECPoint result = ECPoint.POINT_INFINITY;
        ECPoint addend = params.getGenerator();
        for (int i = 0; i < scalar.bitLength(); i++) {
            if (scalar.testBit(i)) {
                result = add(result, addend, a, p);
            }
            addend = add(addend, addend, a, p);
        }
        return result;
    }

    private static ECPoint add(ECPoint left, ECPoint right, BigInteger a, BigInteger p) {
        if (left.equals(ECPoint.POINT_INFINITY)) {
            return right;
        }
        if (right.equals(ECPoint.POINT_INFINITY)) {
            return left;
        }
        BigInteger x1 = left.getAffineX();
        BigInteger y1 = left.getAffineY();
        BigInteger x2 = right.getAffineX();
        BigInteger y2 = right.getAffineY();
        BigInteger slope;
        if (x1.equals(x2)) {
            if (y1.add(y2).mod(p).signum() == 0) {
                return ECPoint.POINT_INFINITY;
            }
            slope = x1.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                    .multiply(y1.shiftLeft(1).modInverse(p)).mod(p);
        } else {
            slope = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
        }
        BigInteger x3 = slope.pow(2).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = slope.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        return new ECPoint(x3, y3);
    }

    private static String unsigned(BigInteger value) {
        return KeyVaultCrypto.b64Url(KeyVaultCrypto.toUnsignedBytes(value));
    }

    /** The BYOK tools and the SDKs send base64url, while the specification says base64: accept either. */
    private static byte[] decodeBase64(String value) {
        if (value == null || value.isBlank()) {
            throw new KeyVaultCrypto.CryptoException("key_hsm is required");
        }
        String normalized = value.strip().replace('+', '-').replace('/', '_');
        while (normalized.endsWith("=")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        try {
            return Base64.getUrlDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            throw new KeyVaultCrypto.CryptoException("key_hsm is not valid base64", e);
        }
    }
}
