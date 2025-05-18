import utilities.KeyConverter;
import utilities.RSAEncryption;
import utilities.RSAKeyUtil;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.*;
import java.util.Objects;

public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;
    private static volatile boolean running = true;
    private static String TRUSTED_SERVER_FINGERPRINT = null;

    public static void main(String[] args) {
        try {
            // Generate client key pair
            KeyPair keyPair = RSAKeyUtil.generateKeyPair();
            System.out.println("Generated client key pair. Fingerprint: " +
                    KeyConverter.getFingerprint(keyPair.getPublic()));

            // Establish connection
            System.out.println("Connecting to server...");
            Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
            socket.setSoTimeout(30000); // 30-second timeout for reads

            // Initialize streams
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

            // ========== KEY EXCHANGE WITH VERIFICATION ==========
            // 1. Receive server's public key and fingerprint
            System.out.println("Performing key exchange...");
            PublicKey serverKey = KeyConverter.stringToPublicKey(in.readLine());
            String serverFingerprint = in.readLine();
            TRUSTED_SERVER_FINGERPRINT = KeyConverter.getFingerprint(serverKey);

            System.out.println("\nServer fingerprint: " + serverFingerprint);
            System.out.println("Calculated fingerprint: " + TRUSTED_SERVER_FINGERPRINT);

            if (!serverFingerprint.equals(TRUSTED_SERVER_FINGERPRINT)) {
                throw new SecurityException(String.format(
                        "DANGER: Server fingerprint mismatch!%nExpected: %s%nReceived: %s%nPossible MITM attack!",
                        TRUSTED_SERVER_FINGERPRINT,
                        serverFingerprint
                ));
            }

            // 2. Send client's public key and fingerprint
            out.println(KeyConverter.keyToString(keyPair.getPublic()));
            out.println(KeyConverter.getFingerprint(keyPair.getPublic()));

            // 3. Receive assigned name
            String clientName = in.readLine();
            System.out.println("\nConnected as: " + clientName);
            System.out.println("Secure channel established. Type 'exit' to quit.");

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
                } catch (Exception e) {
                    if (running) {
                        System.err.println("\nError in receiver thread: " + e.getMessage());
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
                } catch (Exception e) {
                    System.err.println("Error sending message: " + e.getMessage());
                    break;
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
            e.printStackTrace();
        } finally {
            running = false;
            System.out.println("Disconnecting...");
            System.exit(0);
        }
    }
}