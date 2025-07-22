package server;

import crypto.KeyManager;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Server {
    private static final int PORT = 5000;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        UserAuthManager authManager = new UserAuthManager();
        SessionManager sessionManager = new SessionManager();

        KeyManager keyManager = new KeyManager();
        keyManager.generateKeyPair();
        PrivateKey privateKey = keyManager.getPrivateKey();
        PublicKey publicKey = keyManager.getPublicKey();

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
}
