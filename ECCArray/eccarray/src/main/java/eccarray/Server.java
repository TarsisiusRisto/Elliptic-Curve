package eccarray;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Server {

    private static final int PORT = 6001;

    // ------------------------- KEYSERVER ADDRESS --------------------------------------
    private static final String KEY_SERVER_ADDRESS = "localhost";
    // private static final String KEY_SERVER_ADDRESS = "54.179.162.60"; // region Sydney
    // private static final String KEY_SERVER_ADDRESS = "192.168.2.1"; // Ethernet
    // private static final String KEY_SERVER_ADDRESS = "66.94.113.202"; // VPS

    private static final int KEY_SERVER_PORT = 6000;
    private static KeyPair keyPair;
    private static PublicKey clientPublicKey;

    public static void main(String[] args) {
        try {
            // Generate key pair
            keyPair = ECC.generateKeyPair();

            // Store public key in KeyServer
            storePublicKey("Server");

            // Start server socket
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                System.out.println("Server started on port " + PORT);

                try (Socket clientSocket = serverSocket.accept(); PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {

                    System.out.println("Client connected: " + clientSocket.getRemoteSocketAddress() + "\n");
                    while (true) {
                        String encryptedMessage = in.readLine();
                        double startTime = System.nanoTime();
                        if (encryptedMessage != null) {

                            // Dekripsi pesan yang dikirim oleh klien
                            String decryptedMessage = ECC.decrypt(encryptedMessage, keyPair.getPrivate());
                            System.out.println("Receive message from Client : " + decryptedMessage);
                            double endTime = System.nanoTime();

                            // Selalu ambil kunci publik klien untuk setiap siklus komunikasi
                            clientPublicKey = retrievePublicKey("Client");
                            if (clientPublicKey == null) {
                                System.out.println("Client public key not found.");
                                continue;
                            }

                            // Kirim kembali pesan yang didekripsi ke klien (dikenkripsi dengan kunci publik klien)
                            String encryptedResponse = Base64.getEncoder().encodeToString(ECC.encrypt(decryptedMessage, clientPublicKey));
                            System.out.println("Decrypt message from client: " + encryptedResponse + "\n");
                            out.println(encryptedResponse);

                            double latency = (endTime - startTime) / 1000000;
                            System.out.println("Start time : " + startTime + " ms");
                            System.out.println("End time : " + endTime + " ms");
                            System.out.println("Latency : " + latency + " ms\n");
                            // Mengembalikan kunci publik klien ke keyserver setelah setiap siklus
                            returnPublicKey("Client", Base64.getEncoder().encodeToString(clientPublicKey.getEncoded()));

                        } else {
                            System.out.println("No response received.");
                            break;
                        }
                    }
                }
            } catch (IOException e) {
                // e.printStackTrace();
            }

        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    // Method yang digunakan untuk menyimpan kunci publik server ke keyserver
    private static void storePublicKey(String id) throws IOException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("STORE " + id);
            String encodedPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            out.println(encodedPublicKey);
            System.out.println(in.readLine());
        }
    }

    // Method yang digunakan untuk mendapatkan kunci publik client yang ditemukan di keyserver
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

    // Method yang digunakan untuk mengembalikan kunci publik client ke keyserver
    private static void returnPublicKey(String id, String publicKey) throws IOException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("STORE " + id);  // Menginstruksikan untuk menyimpan kunci publik Server
            out.println(publicKey);  // Mengirim kunci publik Server yang diperoleh dari komunikasi
            System.out.println(in.readLine());
        }
    }
}
