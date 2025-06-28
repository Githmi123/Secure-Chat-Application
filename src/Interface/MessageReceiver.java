package Interface;

import java.io.BufferedReader;
import java.io.IOException;

public class MessageReceiver implements Runnable {
	private BufferedReader in;
	
	public MessageReceiver (BufferedReader in) {
		this.in=in;
	}
	
	@Override
	public void run() {
		try {
			String line;
			while ((line= in.readLine()) !=null) {
				// Expected format: MSG:<sender>:<encrypted>:<signature>
				String[] parts=line.split(":",4);
				if (parts.length<4 || !parts[0].equals("MSG")) continue;
				
				String sender=parts[1];
				String encrypted =parts[2];
				String signature= parts[3];
				
				String decrypted = CryptoUtils.decryptMessage(encrypted);
                boolean verified = CryptoUtils.verifySignature(decrypted, signature, sender);
                
                System.out.println("\n[" + sender + "]: " + decrypted + (verified ? "Not tampered" : "Tampered"));
                System.out.print("You: ");  
			}
		} catch (IOException e) {System.err.println("Disconnected from server.");}
	}
}