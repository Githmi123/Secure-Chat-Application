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
		try {
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.startsWith("MSG")) continue;

                String[] parts = line.split(":", 7);
                String encryptedmessageWithAES = parts[2], ivEncoded = parts[3], serverSignPlainText = parts[4];
                String nonce = parts[5];
                long ts = Long.parseLong(parts[6]);

                SecretKey aes = client.getAESKey();
				// System.out.println("AES in receiver: "+aes);
                String serverPub = client.getServerPubKey();

                if (aes == null || serverPub == null) {
                    System.out.println("(Missing key info)");
                    continue;
                }

                String plainText = CryptoUtils.decrypt(encryptedmessageWithAES, aes, Base64.getDecoder().decode(ivEncoded));

                boolean verifyServerSign = CryptoUtils.verify(
                        plainText,
                        Base64.getDecoder().decode(serverSignPlainText),
                        KeyExchangeManager.createPublicKey(serverPub)
                );

                boolean fresh = NonceAndTimestampManager.isFresh(nonce, ts);

                if (verifyServerSign && fresh) {
                    System.out.println("Server: " + plainText);
                    System.out.println("You(client): ");
                } else {
                    System.out.println("(Dropped tampered/expired message)");
                }
            }
        } catch (Exception e) {
            System.out.println("Receiver stopped: " + e.getMessage());
        }
	}
}