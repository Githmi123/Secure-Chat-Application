package src.Interface;

import crypto.CryptoUtils;
import crypto.NonceAndTimestampManager;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.PrintWriter;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class MessageSender {

	public static void sendLoop(Scanner scanner, PrintWriter out, String token, SecretKey aesKey, PrivateKey privateKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, SignatureException {
//		CryptoUtils cryptoUtils = new CryptoUtils();
		while (true) {
			System.out.print("You(client): ");
			String plainText = scanner.nextLine();
			
			 if (plainText.equalsIgnoreCase("LOGOUT")) {
		            try {
		                byte[] iv = CryptoUtils.generateIV();
		                String encryptedMessage = CryptoUtils.encrypt("LOGOUT", aesKey, iv);
		                String signature = Base64.getEncoder().encodeToString(CryptoUtils.sign("LOGOUT", privateKey));
		                String secureMessage = "MSG:" + token + ":" + encryptedMessage + ":" +
		                        Base64.getEncoder().encodeToString(iv) + ":" +
		                        signature + ":" +
		                        NonceAndTimestampManager.generateNonce() + ":" +
		                        Long.toString(System.currentTimeMillis());

		                out.println(secureMessage); 
		                System.out.println("Logout message sent. Exiting...");
		                break; 
		            } catch (Exception e) {
		                System.err.println("Error during logout: " + e.getMessage());
		                break;
		            }
		        }
			 
			byte[] iv = CryptoUtils.generateIV();
			String encryptedMessage = CryptoUtils.encrypt(plainText, aesKey, iv);
			String signature = Base64.getEncoder().encodeToString(CryptoUtils.sign(plainText, privateKey));

			String secureMessage = "MSG:" + token + ":" + encryptedMessage + ":" + Base64.getEncoder().encodeToString(iv) + ":" + signature + ":" + NonceAndTimestampManager.generateNonce() + ":" + Long.toString(System.currentTimeMillis());
			out.println(secureMessage);
			
//			String encrypted = CryptoUtils.encryptMessage(plainText); //////////uncomment////////////////
//            String signature = CryptoUtils.signMessage(plainText); //////////////uncomment/////////////////
            
         // Send: MSG:<token>:<encrypted>:<signature>
//            out.println("MSG:" + token + ":" + encrypted + ":" + signature); //////////////uncomment//////////////////
		}
	}
}
