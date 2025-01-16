package ecchashmap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;

public class KeyServer {

    private static final int PORT = 5000;
    private static final Map<String, String> keyStore = new HashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            // Menambahkan data acak lebih dari 100, 200, 400, 500, dan 1000
            populateRandomData();
            System.out.println("KeyServer started on port " + PORT);
            while (true) {
                new KeyServerHandler(serverSocket.accept()).start();
            }
        } catch (IOException e) {
            // e.printStackTrace();
        }
    }

    // Fungsi untuk menambahkan data acak ke dalam HashMaps
    private static void populateRandomData() {
        Scanner scanner = new Scanner(System.in);
        Random random = new Random();
        System.out.print("Add random data : ");
        int size = scanner.nextInt();
        for (int i = 0; i < size; i++) {
            String id = "Dummy" + (i + 1);
            String publicKey = "PublicKey" + (random.nextInt(size) + 1); // Menghasilkan angka dari 1 hingga 100
            keyStore.put(id, publicKey);
            // System.out.println("Added random entry: " + id + " - " + publicKey + "\n");
        }
        System.out.println("Added random entry : " + keyStore.size() + "\n");
        // displayAllKeys();
        scanner.close();
    }
    // Handler untuk menangani permintaan klien
    private static class KeyServerHandler extends Thread {

        private final Socket clientSocket;

        public KeyServerHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                String request = in.readLine();
                if (request.startsWith("STORE")) {
                    String id = request.split(" ")[1];
                    String publicKey = in.readLine();
                    incrementKeyCount(id, publicKey);
                    out.println("Public key stored successfully.");
                    // System.out.println("\nStored public key for ID: " + id + " - " + publicKey + "\n");
                    // displayAllKeys();
                } else if (request.startsWith("RETRIEVE")) {
                    String id = request.split(" ")[1];
                    String publicKey = keyStore.getOrDefault(id, "Key not found for ID: " + id);
                    if (!publicKey.equals("Key not found : " + id)) {
                        decrementKeyCount(id);
                    }
                    // System.out.println("\nRetrieved public key for : " + id + " - " + publicKey + "\n");
                    out.println(publicKey);
                    // displayAllKeys();
                } else {
                    out.println("Invalid request");
                }
            } catch (IOException e) {
                System.out.println("Connection lost : " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    System.out.println("Errot closing socket: " + e.getMessage());
                }
            }
        }
    }

    // private static void displayAllKeys() { // Menampilkan daftar semua data yang ada di KeyStore
    //     System.out.println("List of all stored keys:");
    //     for (Map.Entry<String, String> entry : keyStore.entrySet()) {
    //         System.out.println("Client ID: " + entry.getKey() + ", Public Key: " + entry.getValue());
    //     }
    //     System.out.println("Total keys: " + keyStore.size() + "\n");
    // }
    private static void decrementKeyCount(String id) {
        if (keyStore.containsKey(id)) {
            keyStore.getOrDefault(id, id); // Hanya menghapus kunci publik yang valid (Server/Client), bukan data dummy
            System.out.println("Key retrieved for : " + id);
            System.out.println("Remaining keys: " + keyStore.size() + " \n");
        }
    }

    // Menambah jumlah kunci saat public key disimpan
    private static void incrementKeyCount(String id, String publicKey) {
        keyStore.put(id, publicKey);
        System.out.println("Key stored from : " + id);
        System.out.println("Total keys: " + keyStore.size() + " \n");
    }
}
