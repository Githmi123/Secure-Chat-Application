package src.Interface;

import crypto.CryptoUtils;
import crypto.KeyExchangeManager;
import crypto.PersistentKeyPair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

public class client {
   static int PORT=5000;

   private static PublicKey publicKey;
   private static PrivateKey privateKey;
   private static String serverPubKey;

   private static SecretKey aesKey;
   
   public static void main (String[] args) throws IOException, SignatureException {
	   InetAddress ipAddress =InetAddress.getLocalHost();
   
	   try (	 
			   	Socket socket =new Socket (ipAddress,PORT);
	           	PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
	            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	            Scanner scanner = new Scanner(System.in)
	        ){

		   System.out.println("Connected to Secure Chat Server");
		   
		   String token=null;
		   while (token==null) {
			System.out.println("1.Login");
			System.out.println("2.Register");
			System.out.print("Enter Option:");
			int choice = Integer.parseInt(scanner.nextLine());

			System.out.print("Enter username: ");
			String username = scanner.nextLine();
			AuthHandler.setUsername(username); 

			PersistentKeyPair persistentKeyPair = new PersistentKeyPair(username);
			KeyPair keyPair = persistentKeyPair.loadOrCreate();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();

			String response = null;
			if (choice == 1) {
				response = AuthHandler.login(username, scanner, out, in);
			} else if (choice == 2) {
				// response = AuthHandler.register(username, scanner, out, in, publicKey);
				 response = AuthHandler.register(scanner, out, in);
			}

			if (response != null && response.startsWith("SUCCESS")) {
				 String[] parts = response.split(":", 3);
                    String encryptedTokenBase64 = parts[1];
                    serverPubKey = parts[2];

                    // Cipher cipher = Cipher.getInstance("RSA");
					Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] decryptedTokenBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedTokenBase64));
                    token = new String(decryptedTokenBytes);
					System.out.println("Check the token : "+token);
			}

		   }
		   
		   System.out.println("Authentication Completed ");	   
		   Thread receiver =new Thread (new MessageReceiver(in));
		   receiver.start();

		   messageSend(scanner, out, token);

	   } catch (IOException e) {
		   System.err.println("Error:"+e.getMessage());
	   } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |
				IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
		   throw new RuntimeException(e);
	   } catch (InvalidAlgorithmParameterException e) {
		   throw new RuntimeException(e);
	   }
   }

	private static void messageSend(Scanner scanner, PrintWriter out, String token) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {
		aesKey = CryptoUtils.generateAESKey();
		KeyExchangeManager keyExchangeManager = new KeyExchangeManager();
		byte[] encryptedAESKey = keyExchangeManager.encryptAESKey(aesKey, keyExchangeManager.createPublicKey(serverPubKey));
		String message = "AESKEY:" + token + ":" + Base64.getEncoder().encodeToString(encryptedAESKey);
		out.println(message);
		MessageSender.sendLoop(scanner, out, token, aesKey, privateKey);
	}

	public static SecretKey getAESKey() {
		System.out.println("aes in clinet: " + aesKey);
		return aesKey;
	}

	public static String getServerPubKey() {
		return serverPubKey;
	}
}
