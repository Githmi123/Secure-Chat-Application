package src.Interface;

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

	private static String username;

	public static String login(Scanner scanner,PrintWriter out,BufferedReader in) throws IOException {
		out.println("login");

		System.out.print("Username:");
		username =scanner.nextLine();
		System.out.print("Password:");
		String password =scanner.nextLine();
		
		out.println("LOGIN:" + username + ":" + password);
		out.flush();
        String response = in.readLine();
//		System.out.println("Response: " + response);
        
		if (response !=null && response.startsWith("SUCCESS")) {
			return response; //return session token
		}
		else {
			System.out.println("Login Failed:"+response);
			return null;
		}
	}

	public static String register(Scanner scanner, PrintWriter out, BufferedReader in, PublicKey publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		out.println("register");

		System.out.print("Username:");
		String username =scanner.nextLine();
		System.out.print("Password:");
		String password =scanner.nextLine();

		PersistentKeyPair persistentKeyPair = new PersistentKeyPair(username);
		KeyPair keyPair = persistentKeyPair.loadOrCreate();

		String encodedPubKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
		System.out.println("Public Key: " + encodedPubKey);
		
		out.println("REGISTER:"+username+":"+password+":"+encodedPubKey+"\n"); // public key also must be sent
		String response =in.readLine();
		
		if (response !=null && response.equals("REGISTERED")) {
			System.out.println("Registration successful.PLease login.");
			return login(scanner,out,in) ;
		}
		else {
			System.out.println("Registration failed!");
			return null;
		}
		
	}

	public static String getUsername(){
		return username;
	}
}
