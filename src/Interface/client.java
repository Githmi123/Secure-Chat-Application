package src.Interface;

import crypto.CryptoUtils;
import crypto.KeyExchangeManager;
import crypto.KeyManager;

import javax.crypto.BadPaddingException;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class client {
   static int PORT=5000;

   private static PublicKey publicKey;
   private static PrivateKey privateKey;
   private static String serverPubKey;
   
   public static void main (String[] args) throws IOException, SignatureException {
	   InetAddress ipAddress =InetAddress.getLocalHost();
   
	   try (	 
			   	Socket socket =new Socket (ipAddress,PORT);
	           	PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
	            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	            Scanner scanner = new Scanner(System.in)
	        ){

		   KeyManager keyManager = new KeyManager();
		   privateKey = keyManager.getPrivateKey();
		   publicKey = keyManager.getPublicKey();


		   System.out.println("Connected to Secure Chat Server");
		   
		   String token=null;
		   while (token==null) {
			   System.out.println("1.Login");
			   System.out.println("2.Register");
			   System.out.print("Enter Option:");
			   int choice =Integer.parseInt(scanner.nextLine());
			   
			   if (choice ==1) {
				   System.out.println("Trying to log in");
				    String response = AuthHandler.login(scanner,out,in);
				   System.out.println("Logged in");
					serverPubKey = response.split(":")[2];
				    token = response.split(":")[1];

			   }
			   else if (choice ==2) {
				   token= AuthHandler.register(scanner,out,in, publicKey);
			   }
		   }
		   
		   System.out.println("Authentication Completed ");
//		   System.out.println("Your Public Key Fingerprint:"+ CryptoUtils.getPublicKeyFingerprint());
		   
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
		System.out.println("Now you can send messages ...");
		SecretKey aesKey = CryptoUtils.generateAESKey();
		KeyExchangeManager keyExchangeManager = new KeyExchangeManager();
		byte[] encryptedAESKey = keyExchangeManager.encryptAESKey(aesKey, keyExchangeManager.createPublicKey(serverPubKey));

		String message = "AESKEY:" + token + ":" + Base64.getEncoder().encodeToString(encryptedAESKey);
		System.out.println(message);
		out.println(message);

//		System.out.println("Enter with whom to chat with: ");
//		String recipient = scanner.nextLine();
//		out.println("RECIPIENT:" + recipient);

		MessageSender.sendLoop(scanner, out, token, aesKey, privateKey);
	}
}
