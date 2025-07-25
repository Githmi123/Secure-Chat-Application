package server;

import crypto.PersistentKeyPair;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.Set;

public class Server {
    private static final int PORT = 5000;

    public static void main(String[] args) throws Exception {
       //UserAuthManager authManager = new UserAuthManager();
        SessionManager sessionManager = new SessionManager();

        // Create the pub-priv keypair only at deployment
        PersistentKeyPair persistentKeyPair = new PersistentKeyPair("server");
        KeyPair keyPair = persistentKeyPair.loadOrCreate("server".toCharArray());
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        UserAuthManager authManager = new UserAuthManager(privateKey);
        
        startConsoleDispatcher(sessionManager);

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                ClientHandler handler = new ClientHandler(clientSocket, authManager, sessionManager, privateKey, publicKey);
                new Thread(handler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

     private static void startConsoleDispatcher(SessionManager sessionManager) {
        new Thread(() -> {
            Scanner sc = new Scanner(System.in);
            while (true) {
                String line = sc.nextLine().trim();
                if (line.isBlank()) continue;

                if (line.startsWith("@")) {
                    int spaceIndex = line.indexOf(' ');
                    if (spaceIndex < 0) {
                        System.out.println("Syntax: @username message");
                        continue;
                    }

                    String user = line.substring(1, spaceIndex);
                    String msg = line.substring(spaceIndex + 1);

                    ClientHandler client = ClientHandler.getOnline(user);
                    if (client == null) {
                        System.out.println(user + " is not online.");
                        continue;
                    }

                    try {
                        client.sendSecure(msg);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    continue;
                }

                System.out.println("Unknown command. Use '@username message' or 'broadcast message'");
            }
        }).start();
    }
}
