package Interface;

import java.io.PrintWriter;
import java.util.Scanner;

public class MessageSender {

	public static void sendLoop(Scanner scanner,PrintWriter out, String token) {
		while (true) {
			System.out.print("You:");
			String plainText = scanner.nextLine();
			
			String encrypted = CryptoUtils.encryptMessage(plainText);
            String signature = CryptoUtils.signMessage(plainText);
            
         // Send: MSG:<token>:<encrypted>:<signature>
            out.println("MSG:" + token + ":" + encrypted + ":" + signature);
		}
	}
}
