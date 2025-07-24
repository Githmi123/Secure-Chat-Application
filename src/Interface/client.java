package src.Interface;

import crypto.CryptoUtils;
import crypto.ECDHUtils;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class client {
   static int PORT=5000;

   private static PublicKey publicKey;
   private static PrivateKey privateKey;
   private static String serverPubKey;

   private static SecretKey aesKey;
   
   public static void main (String[] args) throws Exception {
	   InetAddress ipAddress =InetAddress.getLocalHost();
   
	   try (	 
			   	Socket socket =new Socket (ipAddress,PORT);
	           	PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
	            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	            Scanner scanner = new Scanner(System.in)
	        ){

		   System.out.println("Connected to Secure Chat Server");
		   
		   String line = in.readLine();
		   if (line.startsWith("SERVER PUBLIC KEY:")) {
			   String serverPublicKeyBase64 = line.split(":", 2)[1];
			   PublicKey serverPublicKey = KeyExchangeManager.createPublicKey(serverPublicKeyBase64);
			   AuthHandler.setServerPublicKey(serverPublicKey);
			   serverPubKey = serverPublicKeyBase64;
			   System.out.println("SERVER PUBLIC KEY: " + serverPublicKeyBase64);
		   }
		   
		   String token=null;
		   while (token==null) {
			System.out.println("1.Login");
			System.out.println("2.Register");
			System.out.print("Enter Option:");
			int choice = Integer.parseInt(scanner.nextLine());

			System.out.print("Enter Username: ");
			String username = scanner.nextLine();
			// AuthHandler.setUsername(username);

			PersistentKeyPair persistentKeyPair = new PersistentKeyPair(username);
			KeyPair keyPair = persistentKeyPair.loadOrCreate();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();

			String response = null;
			if (choice == 1) {
				response = AuthHandler.login(username, scanner, out, in);
			} else if (choice == 2) {
				// response = AuthHandler.register(username, scanner, out, in, publicKey);
				 response = AuthHandler.register(username, scanner, out, in);
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
		   
		   performECDHHandshake(token, in, out);

           System.out.println("Handshake OK - secure channel up.");
			
		
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
		// aesKey = CryptoUtils.generateAESKey();
		System.out.println("The AES key now: "+ aesKey);
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

	private static void performECDHHandshake(String token,BufferedReader in, PrintWriter  out) throws Exception {
        KeyPair ecdhPair = ECDHUtils.generate();
        String ecdhPubKeyString  = Base64.getEncoder().encodeToString(ecdhPair.getPublic().getEncoded());
        String ecdhPubKeySign = Base64.getEncoder().encodeToString(CryptoUtils.sign(ecdhPubKeyString, privateKey));

        out.println("ECDH_INIT:" + token + ":" + ecdhPubKeyString + ":" + ecdhPubKeySign);
        out.flush();

        String resp = in.readLine();
        if (resp == null || !resp.startsWith("ECDH_RESP")) {
            throw new IOException("Handshake failed – bad response");
        }
        String[] parts = resp.split(":", 4); 
        String serverPubB64 = parts[2];
        String serverSigB64 = parts[3];

        PublicKey serverLongRSA =
                KeyExchangeManager.createPublicKey(serverPubKey);
        boolean ok = CryptoUtils.verify(serverPubB64,
                                        Base64.getDecoder().decode(serverSigB64),
                                        serverLongRSA);
        if (!ok) throw new SecurityException("Server ECDH signature invalid");

        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey serverECDHPub = kf.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(serverPubB64)));

        aesKey = ECDHUtils.derive(ecdhPair.getPrivate(), serverECDHPub);
    }

}
