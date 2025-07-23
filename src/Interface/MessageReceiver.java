package src.Interface;

import crypto.CryptoUtils;
import crypto.KeyExchangeManager;
import crypto.NonceAndTimestampManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Base64;

import javax.crypto.SecretKey;

public class MessageReceiver implements Runnable {
	private BufferedReader in;
	
	public MessageReceiver (BufferedReader in) {
		this.in=in;
	}
	
	@Override
	public void run() {
		// try {
		// 	String line;
		// 	while ((line= in.readLine()) !=null) {
		// 		// Expected format: MSG:<sender>:<encrypted>:<signature>
		// 		String[] parts=line.split(":",4);
		// 		if (parts.length<4 || !parts[0].equals("MSG")) continue;
				
		// 		String sender=parts[1];
		// 		String encrypted =parts[2];
		// 		String signature= parts[3];
				
//				String decrypted = CryptoUtils.decryptMessage(encrypted); //////////uncomment////////////////
//                boolean verified = CryptoUtils.verifySignature(decrypted, signature, sender); //////////uncomment////////////////
                
//                System.out.println("\n[" + sender + "]: " + decrypted + (verified ? "Not tampered" : "Tampered")); //////////uncomment////////////////
        //         System.out.print("You: ");  
		// 	}
		// } catch (IOException e) {System.err.println("Disconnected from server.");}

		try {
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.startsWith("MSG")) continue;

                String[] p = line.split(":", 7);
                String enc = p[2], ivB64 = p[3], sigB64 = p[4];
                String nonce = p[5];
                long ts = Long.parseLong(p[6]);

                SecretKey aes = client.getAESKey();
				System.out.println("AES in receiver: "+aes);
                String serverPub = client.getServerPubKey();

                if (aes == null || serverPub == null) {
                    System.out.println("(Missing key info)");
                    continue;
                }

                String plain = CryptoUtils.decrypt(enc, aes, Base64.getDecoder().decode(ivB64));

                boolean okSig = CryptoUtils.verify(
                        plain,
                        Base64.getDecoder().decode(sigB64),
                        KeyExchangeManager.createPublicKey(serverPub)
                );

                boolean fresh = NonceAndTimestampManager.isFresh(nonce, ts);

                if (okSig && fresh) {
                    System.out.println("Server: " + plain);
                } else {
                    System.out.println("(Dropped tampered/expired message)");
                }
            }
        } catch (Exception e) {
            System.out.println("Receiver stopped: " + e.getMessage());
        }
	}
}