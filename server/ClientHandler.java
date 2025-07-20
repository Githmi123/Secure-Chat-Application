package server;

import crypto.CryptoUtils;
import crypto.KeyExchangeManager;
import crypto.NonceAndTimestampManager;
import org.bouncycastle.crypto.generators.BCrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

// import java.util.Date;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final UserAuthManager authManager;
    private final SessionManager sessionManager;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private static Map<String, ClientHandler> ONLINE_USERS = new ConcurrentHashMap<>();
    private static Map<String, SecretKey> sessionAESKeys = new ConcurrentHashMap<>();

    private String username;
//    private String recipient;

    private String USER_FILE = "users.txt";


    public ClientHandler(Socket socket, UserAuthManager authManager, SessionManager sessionManager, PrivateKey privateKey, PublicKey publicKey) {
        this.clientSocket = socket;
        this.authManager = authManager;
        this.sessionManager = sessionManager;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public void run() {
        try (
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))
        ) {
//            writer.write("Enter command (register/login):\n");
//            writer.flush();
            System.out.println("New thread created for client");
            String command = reader.readLine();

            if ("register".equalsIgnoreCase(command)) {
                System.out.println("Registering user");
//                writer.write("Username:\n");
//                writer.flush();
                String registerInfo = reader.readLine();
                String[] parts = registerInfo.split(":", 4);
                String user = parts[1];
                String pass = parts[2];
                String pubKey = parts[3];

//                writer.write("Password:\n");
//                writer.flush();
//                String pass = reader.readLine();
//
//                writer.write("PublicKey:\n");
//                writer.flush();
//                String pubKey = reader.readLine();


                if (authManager.registerUser(user, pass, pubKey)) {
                    System.out.println("Registration successful!");
                    writer.write("REGISTERED");

                } else {
                    System.out.println("Registration failed (user exists).\n");
                    writer.write("\n");
                }
                writer.flush();
            }

            if ("login".equalsIgnoreCase(command)) {
                System.out.println("User is logging in");
//                writer.write("Username:\n");
                writer.flush();
                String loginInfo = reader.readLine();
                String[] parts = loginInfo.split(":", 3);
                String user = parts[1];
                String pass = parts[2];

//                writer.write("Password:\n");
//                writer.flush();
//                String pass = reader.readLine();

                if (authManager.loginUser(user, pass)) {
                    String token = sessionManager.createSession(user);
                    this.username = user;
                    ONLINE_USERS.put(user, this);
//                    writer.write("SUCCESS");
//                    writer.flush();
                    String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                    writer.write("SUCCESS:" + token + ":" + publicKeyString + "\n");
                    writer.flush();
                    writer.flush();
                    Logger.logEvent(clientSocket, user, "Login success. Token: " + token);
                    System.out.println("User successfully logged in");



                    String message;
                    while(!Objects.equals(message = reader.readLine(), "LOGOUT")){
                        System.out.println("Receiving messages ...");

                        boolean isSessionValid = sessionManager.isValidSession(username, message.split(":")[1]);
                        if(!isSessionValid){
                            System.out.printf("Session invalid");
                            break;
                        }

                        if(message.startsWith("AESKEY")){
                            System.out.println("AES key received ...");
                            KeyExchangeManager keyExchangeManager = new KeyExchangeManager();
                            SecretKey aesKey = keyExchangeManager.decryptAESKey(Base64.getDecoder().decode(message.split(":")[2].getBytes()), privateKey);
                            sessionAESKeys.put(username, aesKey);
                        }

//                        else if(message.startsWith("RECIPIENT")){
//                            recipient = message.split(":")[1];
//                        }
                        else if(message.startsWith("MSG")){
                            if(!readMessages(message)){
                                break;
                            }
                        }

//                        System.out.println(message);

                        System.out.println("Session valid");




                    }



                } else {
                    Logger.logEvent(clientSocket, user, "Login failed.");
                    writer.write("\n");
                }
                
                writer.flush();
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            if (username != null) {
                sessionManager.invalidateSession(username);
                ONLINE_USERS.remove(username);
                Logger.logEvent(clientSocket, username, "Logged out.");
            }
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private boolean readMessages(String secureMessage) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
//        System.out.println("Sec: " + secureMessage);
        String decryptedMessage = CryptoUtils.decrypt(secureMessage.split(":")[2], sessionAESKeys.get(username), Base64.getDecoder().decode(secureMessage.split(":")[3]));
        String userPubKey;
        System.out.println("Message: " + decryptedMessage);

        try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 4);
                if (parts[0].equals(username)) {
                    userPubKey = parts[3];
                    boolean isVerified = CryptoUtils.verify(decryptedMessage, Base64.getDecoder().decode(secureMessage.split(":")[4]), KeyExchangeManager.createPublicKey(userPubKey));
                    if(!isVerified){
                        System.out.printf("Could not verify sender");
                        return false;
                    }
                    break;
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }


        boolean isNonceAndTimestampValid = NonceAndTimestampManager.isFresh(secureMessage.split(":")[5], Long.parseLong(secureMessage.split(":")[6]));
        if(!isNonceAndTimestampValid){
            System.out.println("Invalid Nonce or Timestamp");
            return false;
        }

//        ClientHandler recipientHandler = ONLINE_USERS.get(recipient);
//        if(recipientHandler != null){
//            try{
//                BufferedWriter recipientWriter = new BufferedWriter(new OutputStreamWriter(recipientHandler.clientSocket.getOutputStream()));
//                recipientWriter.write("FROM:" + username + ":" + decryptedMessage + "\n");
//                recipientWriter.flush();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//        else{
//            System.out.println("Intended recipient is not online");
//        }
        System.out.println(username + " : Decrypted Message " + decryptedMessage);
        return true;
    }

    // private void logEvent(String event) {
    //     try (BufferedWriter bw = new BufferedWriter(new FileWriter("auth_log.txt", true))) {
    //         String clientIP = clientSocket.getInetAddress().getHostAddress();
    //         String logEntry = String.format("[%s] [IP: %s] [User: %s] %s",
    //                 new Date(), clientIP, username != null ? username : "unknown", event);
    //         bw.write(logEntry);
    //         bw.newLine();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
    // }
}
