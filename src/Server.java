import utilities.KeyConverter;
import utilities.RSAEncryption;
import utilities.RSAKeyUtil;


import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class Server {

    private static final int PORT = 1234;
    private static final int MAX_CLIENTS = 10;


    private static final Map<Socket, PublicKey> clientKeys = new ConcurrentHashMap<>();
    private static final Map<Socket, String> clientNames = new ConcurrentHashMap<>();
    private static final KeyPair serverKeyPair;
    private static final ExecutorService threadPool = Executors.newFixedThreadPool(MAX_CLIENTS);
    private static final ScheduledExecutorService cleanupExecutor = Executors.newScheduledThreadPool(1);

    static {
        try {
            File keyFile = new File("server_keypair.ser");
            if (keyFile.exists()) {
                serverKeyPair = RSAKeyUtil.loadKeyPair("server_keypair.ser");
            } else {
                serverKeyPair = RSAKeyUtil.generateKeyPair();
                RSAKeyUtil.saveKeyPair(serverKeyPair, "server_keypair.ser");
                System.out.println("Generated new server keypair. Fingerprint:");
                System.out.println(KeyConverter.getFingerprint(serverKeyPair.getPublic()));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize server keys", e);
        }
    }

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);

            cleanupExecutor.scheduleAtFixedRate(Server::cleanupDisconnectedClients, 1, 1, TimeUnit.MINUTES);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                String clientName = "Client-" + clientNames.size();
                clientNames.put(clientSocket, clientName);

                threadPool.submit(() -> handleClient(clientSocket, clientName));
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        } finally {
            shutdown();
        }
    }

    private static void handleClient(Socket socket, String clientName) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {


            String serverKeyStr = KeyConverter.keyToString(serverKeyPair.getPublic());
            String serverFingerprint = KeyConverter.getFingerprint(serverKeyPair.getPublic());
            out.println(serverKeyStr);
            out.println(serverFingerprint);


            PublicKey clientPublicKey = KeyConverter.stringToPublicKey(in.readLine());
            String clientFingerprint = in.readLine();

            System.out.println("Verifying client key...");
            KeyConverter.verifyKeyFingerprint(clientPublicKey, clientFingerprint);


            clientKeys.put(socket, clientPublicKey);


            out.println(clientName);
            System.out.println(clientName + " connected. Key exchange completed.");


            socket.setSoTimeout(600_000);
            String encryptedMessage;
            while ((encryptedMessage = in.readLine()) != null) {
                System.out.println("[" + clientName + "] Encrypted:\n" +
                        RSAEncryption.formatEncrypted(encryptedMessage, 64));

                String decrypted = RSAEncryption.decrypt(encryptedMessage, serverKeyPair.getPrivate());
                System.out.println("[" + clientName + "] Decrypted: " + decrypted);
            }

        } catch (SecurityException e) {
            System.err.println("SECURITY ALERT with " + clientName + ": " + e.getMessage());
        } catch (SocketTimeoutException e) {
            System.out.println(clientName + " timed out");
        } catch (Exception e) {
            System.out.println("Error with " + clientName + ": " + e.getMessage());
        } finally {
            cleanupClient(socket);
        }
    }

    private static void cleanupClient(Socket socket) {
        try {
            clientKeys.remove(socket);
            clientNames.remove(socket);
            if (!socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            System.err.println("Error cleaning up client: " + e.getMessage());
        }
    }

    private static void cleanupDisconnectedClients() {
        clientKeys.keySet().removeIf(socket -> {
            boolean disconnected = socket.isClosed();
            if (disconnected) {
                clientNames.remove(socket);
            }
            return disconnected;
        });
    }

    private static void shutdown() {
        threadPool.shutdown();
        cleanupExecutor.shutdown();
        try {
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

}

