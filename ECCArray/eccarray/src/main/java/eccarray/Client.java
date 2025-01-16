package eccarray;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    // ------------------------- KEYSERVER ADDRESS --------------------------------------
     private static final String KEY_SERVER_ADDRESS = "localhost";
    //  private static final String KEY_SERVER_ADDRESS = "54.179.162.60"; // region singapore
    //  private static final String KEY_SERVER_ADDRESS = "192.168.2.105"; // Ethernet
    // private static final String KEY_SERVER_ADDRESS = "66.94.113.202"; // VPS

    // ------------------------- SERVER ADDRESS --------------------------------------
     private static final String SERVER_ADDRESS = "localhost";
    //  private static final String SERVER_ADDRESS = "3.0.83.180"; // Region Tokyo
    //  private static final String SERVER_ADDRESS = "192.168.2.3"; // Ethernet
    //  private static final String SERVER_ADDRESS = "192.168.1.64"; // Virtual Box

    private static final int KEY_SERVER_PORT = 6000;
    private static final int PORT = 6001;
    private static KeyPair keyPair;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) {
        try {
            // Generate key pair
            keyPair = ECC.generateKeyPair();

            // Store public key in KeyServer
            storePublicKey("Client");

            // Start client socket
            try (Socket socket = new Socket(SERVER_ADDRESS, PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream())); Scanner scanner = new Scanner(System.in)) {

                System.out.println("Connected to server: " + socket.getRemoteSocketAddress() + "\n");
                while (true) {
                    System.out.print("Enter message to send to server: ");
                    String message = scanner.nextLine();
                    if ("exit".equalsIgnoreCase(message)) {
                        System.out.println("Disconnected");
                        break;
                    }

                    // Retrieve server public key from KeyServer
                    serverPublicKey = retrievePublicKey("Server");
                    if (serverPublicKey == null) {
                        System.out.println("Server public key not found.");
                        return;
                    }
                    String encryptedMessage = Base64.getEncoder().encodeToString(ECC.encrypt(message, serverPublicKey));
                    System.out.println("Sending encrypted message: " + encryptedMessage + "\n");
                    double startTime = System.nanoTime(); // Start time
                    out.println(encryptedMessage);
                    out.flush();

                    // Read response from server
                    String encryptedResponse = in.readLine();

                    if (encryptedResponse != null) {
                        String decryptedResponse = ECC.decrypt(encryptedResponse, keyPair.getPrivate());
                        System.out.println("Received message from server: " + decryptedResponse);
                        double endTime = System.nanoTime();
                        // Print latency
                        double latency = (endTime - startTime) / 1000000;
                        System.out.println("Start time : " + startTime + " ms");
                        System.out.println("End time : " + endTime + " ms");
                        System.out.println("Latency : " + latency + " ms\n");
                    } else {
                        System.out.println("No response received.");
                        break;
                    }
                    // Mengembalikan kunci publik server ke keyserver
                    returnPublicKey("Server", Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));
                }
            } catch (IOException e) {
                // e.printStackTrace();
            }

        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    // Method yang digunakan untuk menyimpan kunci publik Client di KeyServer
    private static void storePublicKey(String id) throws IOException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("STORE " + id);
            String encodedPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            out.println(encodedPublicKey);
            System.out.println(in.readLine());
        }
    }

    // Method yang digunakan untuk mendapatkan kunci publik Server yang telah disimpan di KeyServer
    private static PublicKey retrievePublicKey(String id) throws IOException, GeneralSecurityException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("RETRIEVE " + id);
            String response = in.readLine();
            if (response.startsWith("Key not found")) {
                return null;
            }

            byte[] keyBytes = Base64.getDecoder().decode(response);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            return publicKey;
        }
    }

    // Method yang digunakan untuk mengembalikan kunci publik Server ke KeyServer ketika client sudah mengirim pesan
    private static void returnPublicKey(String id, String publicKey) throws IOException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("STORE " + id);  // Menginstruksikan untuk menyimpan kunci publik Server
            out.println(publicKey);  // Mengirim kunci publik Server yang diperoleh dari komunikasi
            System.out.println(in.readLine());
        }
    }
}