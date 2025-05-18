import utilities.KeyConverter;
import utilities.RSAEncryption;
import utilities.RSAKeyUtil;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.*;
import java.util.Objects;

public class Client {
    private static final String TRUSTED_SERVER_FINGERPRINT = "y2U0TsNroEf+M7mlIF8MofyE439EuwCBL9yUKM503ZQ=";
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;
    private static volatile boolean running = true;

    public static void main(String[] args) {
        try {
            // Generate client key pair
            KeyPair keyPair = RSAKeyUtil.generateKeyPair();

            // Establish connection
            Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
            socket.setSoTimeout(30000); // 5-second timeout for reads

            // Initialize streams
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

            // ========== KEY EXCHANGE WITH VERIFICATION ==========
            // 1. Receive server's public key and fingerprint
            PublicKey serverKey = KeyConverter.stringToPublicKey(in.readLine());
            String serverFingerprint = in.readLine();

            if (!serverFingerprint.equals(TRUSTED_SERVER_FINGERPRINT)) {
                throw new SecurityException("""
            DANGER: Server fingerprint mismatch!
            Expected: %s
            Received: %s
            Possible MITM attack! Disconnecting...""".formatted(
                        TRUSTED_SERVER_FINGERPRINT,
                        serverFingerprint
                ));
            }





            out.println(KeyConverter.keyToString(keyPair.getPublic()));
            out.println(KeyConverter.getFingerprint(keyPair.getPublic()));

            // 4. Receive assigned name
            String clientName = in.readLine();
            System.out.println("\nConnected as: " + clientName);
            System.out.println("Secure channel established. You may begin messaging.");

            // ========== MESSAGE PROCESSING ==========
            // Start message receiver thread
            ExecutorService executor = Executors.newSingleThreadExecutor();
            executor.submit(() -> {
                try {
                    while (running) {
                        String encrypted = in.readLine();
                        if (encrypted == null) {
                            System.err.println("\nServer disconnected");
                            break;
                        }
                        String decrypted = RSAEncryption.decrypt(encrypted, keyPair.getPrivate());
                        System.out.println("\n[Server] " + decrypted);
                        System.out.print("Your message: ");
                    }
                } catch (RSAEncryption.RSAOperationException e) {
                    System.err.println("\nDecryption error: " + e.getMessage());
                } catch (IOException e) {
                    if (running) {
                        System.err.println("\nConnection error: " + e.getMessage());
                    }
                }
            });

            // Message sender loop
            while (running) {
                try {
                    System.out.print("Your message: ");
                    String message = console.readLine();


                    if (message == null || "exit".equalsIgnoreCase(message)) {
                        break;
                    }

                    String encrypted = RSAEncryption.encrypt(Objects.requireNonNull(message), serverKey);
                    out.println(encrypted);
                } catch (RSAEncryption.RSAOperationException e) {
                    System.err.println("Encryption error: " + e.getMessage());
                }
            }

        } catch (SecurityException e) {
            System.err.println("SECURITY ALERT: " + e.getMessage());
        } catch (UnknownHostException e) {
            System.err.println("Server not found: " + e.getMessage());
        } catch (ConnectException e) {
            System.err.println("Connection refused - is the server running?");
        } catch (SocketTimeoutException e) {
            System.err.println("Connection timed out");
        } catch (IOException e) {
            System.err.println("Network error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
        } finally {
            running = false;
            System.out.println("Disconnecting...");
        }
    }
}