package src.Interface;

import crypto.KeyExchangeManager;
import crypto.PersistentKeyPair;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

public class AuthHandler {

	// private static String username;
	private static PublicKey serverPublicKey;

	public static void setServerPublicKey(PublicKey key) {
	        serverPublicKey = key;
	}
 	
	public static String login(String username, Scanner scanner, PrintWriter out, BufferedReader in) throws IOException {
			out.println("login");
			// AuthHandler.setUsername(username);
	        
			System.out.print("Password:");
			String password = scanner.nextLine();

			String encryptedPassword = KeyExchangeManager.encryptPassword(password, serverPublicKey);
			out.println("LOGIN:" + username + ":" + encryptedPassword);
            out.flush();

			String response = in.readLine();
			if (response == null || response.isBlank() || response.startsWith("FAILED")) {
				System.out.println("Login Failed.");
				return null;
			}

			if (response.startsWith("SUCCESS")) {
				System.out.println("Successful");
				return response;
			}

			System.out.println("Unexpected response: " + response);
			return null;
}

 public static String register(String username,Scanner scanner, PrintWriter out, BufferedReader in) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        out.println("register");

        // System.out.print("Username: ");
        // username = scanner.nextLine();
        System.out.print("Password: ");
        String password = scanner.nextLine();

        
        
        PersistentKeyPair persistentKeyPair = new PersistentKeyPair(username);
        KeyPair keyPair = persistentKeyPair.loadOrCreate();

        String encodedPubKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
		String encryptedPassword = KeyExchangeManager.encryptPassword(password, serverPublicKey);

        String registerMessage = "REGISTER:" + username + ":" + encryptedPassword + ":" + encodedPubKey;
        out.println(registerMessage);
        out.flush();

        String response = in.readLine();
        if (response != null && response.equals("REGISTERED")) {
            System.out.println("Registration successful. Please login.");
            return login(username, scanner, out, in);
        } else {
            System.out.println("Registration failed! Username already taken.");
            return null;
        }
    }

 public static void logout(PrintWriter out) {
	    out.println("LOGOUT");
	    out.flush();
	    System.out.println("You have been logged out.");
	    // setUsername(null); // clear static username
	}
 
	// public static String getUsername(){
	// 	return username;
	// }

	// public static void setUsername(String user) {
	// 	username = user;	
	// }

}
