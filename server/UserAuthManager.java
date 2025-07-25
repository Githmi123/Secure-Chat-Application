package server;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import crypto.KeyExchangeManager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

public class UserAuthManager {
    private static final String USER_FILE = "users.txt";
    private final PrivateKey privateKey;
    
    public UserAuthManager(PrivateKey privateKey){
    	this.privateKey = privateKey;
    	
        try{
            File file = new File(USER_FILE);
            if(!file.exists()){
                file.createNewFile();
                System.out.println("New file created to store user login data ...");
            }
        } catch (Exception e) {
            System.out.println("An error occured");
            e.printStackTrace();
        }
    }

    public boolean registerUser(String username, String encryptedPasswordBase64, String publicKey) {
    	String decryptedPassword = KeyExchangeManager.decryptPassword(encryptedPasswordBase64, privateKey);
    	try (BufferedWriter writer = new BufferedWriter(new FileWriter("users.txt", true))) {
        if (userExists(username)) {
            System.out.println("User exists : error");
            return false;
        }

        byte[] salt = generateSalt();
        String hashedPassword = hashPassword(decryptedPassword, salt);
        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        writer.write(username + ":" + hashedPassword + ":" + encodedSalt + ":" + publicKey);
        writer.newLine();
        return true;
        } 
        
        catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean loginUser(String username, String encryptedPasswordBase64) throws NoSuchAlgorithmException {
        try {
            String decryptedPassword = KeyExchangeManager.decryptPassword(encryptedPasswordBase64, privateKey);

    	try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 4);
                if (parts[0].equals(username)) {
                    String storedHash = parts[1];
                    byte[] salt = Base64.getDecoder().decode(parts[2]);
                    String hashedInput = hashPassword(decryptedPassword, salt);
                    return storedHash.equals(hashedInput);
                }
            }
            System.out.println("Finished login");
    	}
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public String getPublicKey(String username) {
        try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 4);
                if (parts[0].equals(username)) return parts[3];
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private boolean userExists(String username) {
//        System.out.println("Checking if user exists ...");

        try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(username + ":")) return true;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

   public static String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt);
        byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
}

}
