package utilities;

import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class KeyConverter {

    public static String keyToString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey stringToPublicKey(String keyStr) throws RSAEncryption.RSAOperationException {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RSAEncryption.RSAOperationException("Invalid public key format", e);
        }
    }

    public static PrivateKey stringToPrivateKey(String keyStr) throws RSAEncryption.RSAOperationException {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RSAEncryption.RSAOperationException("Invalid private key format", e);
        }
    }

    public static String getFingerprint(Key key) throws NoSuchAlgorithmException {
        byte[] keyBytes = key.getEncoded();
        byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(keyBytes);
        return Base64.getEncoder().encodeToString(fingerprint);
    }

    public static String getFormattedFingerprint(Key key) throws NoSuchAlgorithmException {
        byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fingerprint.length; i++) {
            sb.append(String.format("%02X", fingerprint[i]));
            if (i < fingerprint.length - 1) {
                sb.append(":");
                if ((i + 1) % 8 == 0) sb.append("\n");
            }
        }
        return sb.toString();
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