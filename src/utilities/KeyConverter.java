package utilities;

import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class KeyConverter {

    public static String keyToString(Key key) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey stringToPublicKey(String keyStr) throws RSAEncryption.RSAOperationException {
        if (keyStr == null || keyStr.isEmpty()) {
            throw new IllegalArgumentException("Public key string cannot be null or empty");
        }
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RSAEncryption.RSAOperationException("Invalid public key format", e);
        }
    }

    public static String getFingerprint(Key key) throws NoSuchAlgorithmException {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        byte[] keyBytes = key.getEncoded();
        byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(keyBytes);
        return Base64.getEncoder().encodeToString(fingerprint);
    }

    public static void verifyKeyFingerprint(Key key, String expectedFingerprint)
            throws NoSuchAlgorithmException, SecurityException {
        String actual = getFingerprint(key);
        if (!actual.equals(expectedFingerprint)) {
            throw new SecurityException(
                    "Key fingerprint mismatch!\nExpected: " + expectedFingerprint +
                            "\nActual:   " + actual
            );
        }
    }
}