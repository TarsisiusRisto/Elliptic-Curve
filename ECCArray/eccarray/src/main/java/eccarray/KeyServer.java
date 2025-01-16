package eccarray;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

// Custom class to represent key entry
class KeyEntry {

    String id;
    String publicKey;

    public KeyEntry(String id, String publicKey) {
        this.id = id;
        this.publicKey = publicKey;
    }
}

public class KeyServer {

    private static final int PORT = 6000;
    private static final List<KeyEntry> keyStore = new ArrayList<>();

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

    // Fungsi untuk menambahkan data acak ke dalam ArrayList
    private static void populateRandomData() {
        Scanner scanner = new Scanner(System.in);
        Random random = new Random();
        System.out.print("Add random data : ");
        int size = scanner.nextInt();
        for (int i = 0; i < size; i++) {
            String id = "Dummy" + (i + 1);
            String publicKey = "PublicKey" + (random.nextInt(size) + 1); // Menghasilkan angka dari 1 hingga 100
            keyStore.add(new KeyEntry(id, publicKey));
        }
        System.out.println("Added random entry : " + keyStore.size() + "\n");
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
                } else if (request.startsWith("RETRIEVE")) {
                    String id = request.split(" ")[1];
                    String publicKey = retrievePublicKey(id);
                    out.println(publicKey);
                } else {
                    out.println("Invalid request");
                }
            } catch (IOException e) {
                // e.printStackTrace();
            }
        }
    }

    // Mengambil kunci publik berdasarkan ID dari ArrayList
    private static String retrievePublicKey(String id) {
        for (KeyEntry entry : keyStore) {
            if (entry.id.equals(id)) {
                decrementKeyCount(id);
                return entry.publicKey;
            }
        }
        return "Key not found for ID: " + id;
    }

    private static void decrementKeyCount(String id) {
        keyStore.removeIf(entry -> entry.id.equals(id));
        System.out.println("Key retrieved for : " + id);
        System.out.println("Remaining keys: " + keyStore.size() + " \n");
    }

    // Menambah jumlah kunci saat public key disimpan
    private static void incrementKeyCount(String id, String publicKey) {
        keyStore.add(new KeyEntry(id, publicKey));
        System.out.println("Key stored from : " + id);
        System.out.println("Total keys: " + keyStore.size() + " \n");
    }
}