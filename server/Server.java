package server;

import crypto.KeyManager;
import crypto.PersistentKeyPair;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class Server {
    private static final int PORT = 5000;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        UserAuthManager authManager = new UserAuthManager();
        SessionManager sessionManager = new SessionManager();

        // Create the pub-priv keypair only at deployment
        PersistentKeyPair persistentKeyPair = new PersistentKeyPair("server");
        KeyPair keyPair = persistentKeyPair.loadOrCreate();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();


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
