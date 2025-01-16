package ecdh;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Server {

    private KeyPair serverKeyPair;
    private PrivateKey serverPrivateKey;
    private PublicKey clientPublicKey;
    private static final int PORT = 7001;

    public Server() {
        try {
            // Generate ECC key pair for the server
            ECDH ecdh = new ECDH();
            serverKeyPair = ecdh.generateECCKeyPair();
            serverPrivateKey = serverKeyPair.getPrivate();

            startServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is listening on port " + PORT);

            try (Socket socket = serverSocket.accept()) {
                System.out.println("Client connected: " + socket.getRemoteSocketAddress());

                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                // Send server's public key to the client
                String serverEncodedPublicKey = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
                out.println(serverEncodedPublicKey);

                // Receive client's public key
                String clientPublicKeyStr = in.readLine();
                byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyStr);
                clientPublicKey = ECDH.getPublicKeyFromEncoded(clientPublicKeyBytes);

                // Generate shared secret using ECDH
                byte[] sharedSecret = ECDH.generateECDHSharedSecret(serverPrivateKey, clientPublicKey);

                while (true) {
                    // Receive encrypted message and decode
                    String encryptedMessageStr = in.readLine();
                    if (encryptedMessageStr == null) {
                        break;
                    }

                    byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageStr);
                    String decryptedMessage = new String(ECDH.decryptWithECC(serverPrivateKey, encryptedMessage));
                    System.out.println("Received decrypted message from client: " + decryptedMessage);

                    // Encrypt the message and send it back to the client
                    byte[] responseMessage = ECDH.encryptWithECC(clientPublicKey, decryptedMessage.getBytes());
                    String responseMessageStr = Base64.getEncoder().encodeToString(responseMessage);
                    out.println(responseMessageStr);

                    System.out.println("Sent encrypted response to client.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Server();
    }
}
