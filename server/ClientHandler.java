package server;

import crypto.CryptoUtils;
import crypto.ECDHUtils;
import crypto.KeyExchangeManager;
import crypto.NonceAndTimestampManager;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final UserAuthManager authManager;
    private final SessionManager sessionManager;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private static Map<String, ClientHandler> ONLINE_USERS = new ConcurrentHashMap<>();
    private static Map<String, SecretKey> sessionAESKeys = new ConcurrentHashMap<>();

    private String username;

    // private BufferedWriter writer;
    private String         user;
    private BufferedReader in;
    private BufferedWriter out;

    public ClientHandler(Socket socket, UserAuthManager authManager, SessionManager sessionManager, PrivateKey privateKey, PublicKey publicKey) {
        this.clientSocket = socket;
        this.authManager = authManager;
        this.sessionManager = sessionManager;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

   @Override public void run() {
        try {
            in  = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

            System.out.println("\nNew thread created for client");
            String serverPublicKeyString1 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            out.write("SERVER PUBLIC KEY:" + serverPublicKeyString1 + "\n");
            out.flush();

            for (String line; (line = in.readLine()) != null; ) {
                if (line.equalsIgnoreCase("register")) { handleRegister(); }
                else if (line.equalsIgnoreCase("login")) { handleLogin();    }
                else if (line.startsWith("ECDH_INIT"))   { handleECDH(line);  }
                else if (line.startsWith("MSG"))         { handleMsg(line);   }
                else if (line.equalsIgnoreCase("LOGOUT")) {handleLogout();}
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally { cleanup(); }
    }

    private void handleRegister() throws Exception {
        String userInfo = in.readLine();                
        String[] infoParts = userInfo.split(":",4);
        boolean isRegistered = authManager.registerUser(infoParts[1],infoParts[2],infoParts[3]);
        out.write(isRegistered ? "REGISTERED\n" : "REGISTER_FAILED\n");
        if(isRegistered){
            System.out.println("Registration successful!");
        }
        else{
            System.out.println("Registration failed (user exists).\n");
        }
        out.flush();
    }

    private void handleLogin() throws Exception {
//        System.out.println("User is logging in");
        String loginInfo = in.readLine(); 
        
        if (loginInfo == null) {
            System.out.println("Login info not received. Client might have disconnected.");
            return;
        }
        
        String[] loginInfoParts = loginInfo.split(":",3);

        if (!authManager.loginUser(loginInfoParts[1],loginInfoParts[2])) {
            out.write("FAILED\n"); 
            out.flush(); 
            Logger.logEvent(clientSocket, user, "Login failed.");
            return;
        }

        user = loginInfoParts[1];
        ONLINE_USERS.put(user,this);

        String token = sessionManager.createSession(user);

        PublicKey clientPublicKey = KeyExchangeManager.createPublicKey(authManager.getPublicKey(user));
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        String encryptedToken = Base64.getEncoder().encodeToString(cipher.doFinal(token.getBytes()));

        out.write("SUCCESS:" + encryptedToken + ":" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");
        out.flush();

        Logger.logEvent(clientSocket, user, "Login success. Encrypted token: " + encryptedToken);
//        System.out.println("User successfully logged in");
    }

    private void handleECDH(String msg) throws Exception {
        String[] ecdhInfoParts = msg.split(":",4);

        if (!sessionManager.isValidSession(user, ecdhInfoParts[1])) { return; }

        String ecdhClientPublicKeyString = ecdhInfoParts[2];
        String ecdhClientPublicKeySign   = ecdhInfoParts[3];

        PublicKey clientRsaPublicKey = KeyExchangeManager.createPublicKey(authManager.getPublicKey(user));

        if (!CryptoUtils.verify(ecdhClientPublicKeyString,Base64.getDecoder().decode(ecdhClientPublicKeySign),clientRsaPublicKey)) {
            System.out.println("Bad ECDH signature from " + user);
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey clientEpPub = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(ecdhClientPublicKeyString)));

        KeyPair serverEpPair = ECDHUtils.generate();
        SecretKey aes = ECDHUtils.derive(serverEpPair.getPrivate(), clientEpPub);
        sessionAESKeys.put(user, aes);

        String serverPubB64 = Base64.getEncoder().encodeToString(serverEpPair.getPublic().getEncoded());
        String serverSigB64 = Base64.getEncoder().encodeToString(CryptoUtils.sign(serverPubB64, privateKey));

        out.write("ECDH_RESP:" + ecdhInfoParts[1] + ":" + serverPubB64 + ":" + serverSigB64 + "\n");
        out.flush();

        System.out.println("ECDH handshake complete with " + user + "\n");
    }

     private void handleMsg(String frame) throws Exception {
        String[] messageInfoParts = frame.split(":", 7);
        String tok = messageInfoParts[1];
        if (!sessionManager.isValidSession(user, tok)) return;

        SecretKey aes = sessionAESKeys.get(user);
        if (aes == null) {
            System.out.println("AES key missing for " + user);
            return;
        }
        
        String nonce = messageInfoParts[5];
        long timestamp;
        try {
            timestamp = Long.parseLong(messageInfoParts[6]);
        } catch (NumberFormatException e) {
            System.out.println("Invalid timestamp: " + messageInfoParts[6]);
            return;
        }

        boolean isFresh = NonceAndTimestampManager.isFresh(nonce, timestamp);
        if (!isFresh) {
            System.out.println("Invalid nonce/timestamp! Possible replay.");
            return;
        }

        String plain = CryptoUtils.decrypt(messageInfoParts[2], aes,
                            Base64.getDecoder().decode(messageInfoParts[3]));
        System.out.println(user + " > " + plain);
        if (plain.equalsIgnoreCase("LOGOUT")) {
            handleLogout();
            return;
        }
    }

    public void sendSecure(String plain) throws Exception {
        SecretKey aes = sessionAESKeys.get(user);
        if (aes == null) { System.out.println("AES not ready for "+user); return; }

        byte[] iv  = CryptoUtils.generateIV();
        String enc = CryptoUtils.encrypt(plain, aes, iv);
        String sig = Base64.getEncoder()
                           .encodeToString(CryptoUtils.sign(plain, privateKey));

        String token = sessionManager.getToken(user);

        String frame = "MSG:" + token + ":" + enc + ":" +
                       Base64.getEncoder().encodeToString(iv) + ":" + sig + ":" +
                       NonceAndTimestampManager.generateNonce() + ":" +
                       System.currentTimeMillis();

        out.write(frame + "\n");
        out.flush();
    }

      private void cleanup() {
        try {
            if (user != null) {
                sessionManager.invalidateSession(user);
                ONLINE_USERS.remove(user);
            }
            clientSocket.close();
        } catch (IOException ignored) {}
    }

    public static ClientHandler getOnline(String user) {
        return ONLINE_USERS.get(user);
    }

    public void handleLogout(){
        try {
        //System.out.println("User requested logout.");
        System.out.println("User <"+user+"> Logged out");
        out.write("LOGGED_OUT\n");
        out.flush();

        sessionManager.invalidateSession(user);
        ONLINE_USERS.remove(user);
        Logger.logEvent(clientSocket, user, "User logged out.");
         
    } catch (IOException e) {
        System.out.println("Logout failed: " + e.getMessage());
    }
    }

}
