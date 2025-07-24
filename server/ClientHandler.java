package server;

import crypto.CryptoUtils;
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
    private String USER_FILE = "users.txt";


    public ClientHandler(Socket socket, UserAuthManager authManager, SessionManager sessionManager, PrivateKey privateKey, PublicKey publicKey) {
        this.clientSocket = socket;
        this.authManager = authManager;
        this.sessionManager = sessionManager;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @SuppressWarnings("static-access")
    @Override
public void run() {
    try (
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))
    ) {
        System.out.println("New thread created for client");
        String serverPublicKeyString1 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        writer.write("SERVER PUBLIC KEY:" + serverPublicKeyString1 + "\n");
        writer.flush();
        
        String command;
        while ((command = reader.readLine()) != null) {

            if ("register".equalsIgnoreCase(command)) {
                System.out.println("Registering user");
                String registerInfo = reader.readLine();
                String[] parts = registerInfo.split(":", 4);
                String user = parts[1];
                String pass = parts[2];
                String pubKey = parts[3];

                if (authManager.registerUser(user, pass, pubKey)) {
                    writer.write("REGISTERED\n");
                    System.out.println("Registration successful!");
                } else {
                    writer.write("REGISTER_FAILED\n");
                    System.out.println("Registration failed (user exists).");
                }
                writer.flush();
            }

            else if ("login".equalsIgnoreCase(command)) {
                System.out.println("User is logging in");
                String loginInfo = reader.readLine();

                if (loginInfo == null) {
                    System.out.println("Login info not received. Client might have disconnected.");
                    break;
                }

                String[] parts = loginInfo.split(":", 3);
                String user = parts[1];
                String pass = parts[2];

                if (authManager.loginUser(user, pass)) {
                    String token = sessionManager.createSession(user);
                    this.username = user;
                    ONLINE_USERS.put(user, this);
                    String pubKeyString = getUserPublicKey(username);
                    PublicKey clientPublicKey = KeyExchangeManager.createPublicKey(pubKeyString);

                    String serverPublicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

                    // Cipher cipher = Cipher.getInstance("RSA");
                    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                    byte[] encryptedTokenBytes = cipher.doFinal(token.getBytes());
                    String encryptedToken = Base64.getEncoder().encodeToString(encryptedTokenBytes);

                    // writer.write("SUCCESS:" + encryptedToken + ":" + pubKeyString + "\n");
                     writer.write("SUCCESS:" + encryptedToken + ":" + serverPublicKeyString + "\n");


                    // String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

                    // writer.write("SUCCESS:" + token + ":" + publicKeyString + "\n");

                    writer.flush();
                    Logger.logEvent(clientSocket, user, "Login success. Token: " + token);
                    System.out.println("User successfully logged in");

                    new Thread(() -> sendConsoleMessages(writer, token)).start();

                    String message;
                   /* while ((message = reader.readLine()) != null && !message.equals("LOGOUT")) {
                       boolean isSessionValid = sessionManager.isValidSession(username, message.split(":")[1]);
                        if (!isSessionValid) {
                            System.out.println("Session invalid");
                            break;
                        }*/
                    while ((message = reader.readLine()) != null) {
                        
                        if (message.startsWith("AESKEY")) {
                            System.out.println("AES key received ...");
                            KeyExchangeManager keyExchangeManager = new KeyExchangeManager();
                            SecretKey aesKey = keyExchangeManager.decryptAESKey(
                                Base64.getDecoder().decode(message.split(":")[2].getBytes()), privateKey
                            );
                            sessionAESKeys.put(username, aesKey);
                        } else if (message.startsWith("MSG")) {
                            String decryptedMessage = readMessages(message);
                            if (decryptedMessage == null) {
                                // verification or freshness failed
                                break;
                            }
                            if (decryptedMessage.equalsIgnoreCase("LOGOUT")) {
                                System.out.println("User requested logout.");
                                writer.write("LOGGED_OUT\n");
                                writer.flush();

                                sessionManager.invalidateSession(username);
                                ONLINE_USERS.remove(username);
                                Logger.logEvent(clientSocket, username, "User logged out.");
                                break;
                            }
                        }

                        System.out.println("Session valid");
                    }
                } else {
                    writer.write("FAILED\n");
                    writer.flush();
                    Logger.logEvent(clientSocket, user, "Login failed.");
                }
            }
        }

    } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
             BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException |
             SignatureException | InvalidKeySpecException e) {
        e.printStackTrace();
    } finally {
        try {
            if (username != null) {
                sessionManager.invalidateSession(username);
                ONLINE_USERS.remove(username);
                Logger.logEvent(clientSocket, username, "Logged out.");
            }
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


    private String readMessages(String secureMessage) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
        String decryptedMessage = CryptoUtils.decrypt(secureMessage.split(":")[2], sessionAESKeys.get(username), Base64.getDecoder().decode(secureMessage.split(":")[3]));
        String userPubKey;

        try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 4);
                if (parts[0].equals(username)) {
                    userPubKey = parts[3];
                    boolean isVerified = CryptoUtils.verify(decryptedMessage, Base64.getDecoder().decode(secureMessage.split(":")[4]), KeyExchangeManager.createPublicKey(userPubKey));
                    if(!isVerified){
                        System.out.printf("Could not verify sender");
                        return null;
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
            return null;
        }

        System.out.println(username + " : Decrypted Message " + decryptedMessage);
        return decryptedMessage;
    }

    private String getUserPublicKey(String username) {
        try (BufferedReader br = new BufferedReader(new FileReader("users.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 4); 
                if (parts.length == 4 && parts[0].equals(username)) {
                    return parts[3];
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null; 
    }

    private void sendConsoleMessages(BufferedWriter writer, String token) {
        try (BufferedReader console = new BufferedReader(new InputStreamReader(System.in))) {
            String plain;
            while (true){
                 System.out.print("You(server): ");
                plain = console.readLine();

                if (plain == null) break; 

                SecretKey aesKey = sessionAESKeys.get(username);
                if (aesKey == null) { System.out.println("AES key not ready."); continue; }

                byte[] iv = CryptoUtils.generateIV();
                String enc = CryptoUtils.encrypt(plain, aesKey, iv);
                String sig = Base64.getEncoder().encodeToString(CryptoUtils.sign(plain, privateKey));

                String secure = "MSG:" + token + ":" + enc + ":" +
                        Base64.getEncoder().encodeToString(iv) + ":" + sig + ":" +
                        NonceAndTimestampManager.generateNonce() + ":" + System.currentTimeMillis();

                writer.write(secure + "\n");
                writer.flush();
            }
        } catch (Exception e) { System.out.println("Console‑send stopped: " + e); }
    }


}
