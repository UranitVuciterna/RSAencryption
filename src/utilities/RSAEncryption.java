package utilities;

import javax.crypto.*;
import java.security.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class RSAEncryption {
    private static final String RSA_MODE = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static String encrypt(String message, PublicKey publicKey) throws RSAOperationException {
        try {
            if (message == null || message.isEmpty()) {
                throw new RSAOperationException("Message cannot be null or empty");
            }
            if (publicKey == null) {
                throw new RSAOperationException("Public key cannot be null");
            }

            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new RSAOperationException("RSA algorithm not available", e);
        } catch (NoSuchPaddingException e) {
            throw new RSAOperationException("Invalid padding configuration", e);
        } catch (InvalidKeyException e) {
            throw new RSAOperationException("Invalid public key", e);
        } catch (IllegalBlockSizeException e) {
            throw new RSAOperationException("Message too long for RSA encryption", e);
        } catch (BadPaddingException e) {
            throw new RSAOperationException("Padding error during encryption", e);
        }
    }

    public static String decrypt(String encryptedMessage, PrivateKey privateKey) throws RSAOperationException {
        try {

            if (encryptedMessage == null || encryptedMessage.isEmpty()) {
                throw new RSAOperationException("Encrypted message cannot be null or empty");
            }
            if (privateKey == null) {
                throw new RSAOperationException("Private key cannot be null");
            }

            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (NoSuchAlgorithmException e) {
            throw new RSAOperationException("RSA algorithm not available", e);
        } catch (NoSuchPaddingException e) {
            throw new RSAOperationException("Invalid padding configuration", e);
        } catch (InvalidKeyException e) {
            throw new RSAOperationException("Invalid private key", e);
        } catch (IllegalBlockSizeException e) {
            throw new RSAOperationException("Decryption block size error", e);
        } catch (BadPaddingException e) {
            throw new RSAOperationException("Padding error during decryption - possible corrupt message", e);
        }
    }


    public static class RSAOperationException extends Exception {
        public RSAOperationException(String message) {
            super(message);
        }
        public RSAOperationException(String message, Throwable cause) {
            super(message, cause);
        }
    }


    public static String formatEncrypted(String encrypted, int lineLength) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < encrypted.length(); i += lineLength) {
            int end = Math.min(encrypted.length(), i + lineLength);
            builder.append(encrypted, i, end).append("\n");
        }
        return builder.toString();
    }
}