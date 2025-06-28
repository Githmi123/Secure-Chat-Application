package Interface;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;

public class client {
   static int PORT=6000;
   
   public static void main (String[] args) throws IOException {
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
			   int choice =Integer.parseInt(scanner.nextLine());
			   
			   if (choice ==1) {
				   token=AuthHandler.login(scanner.out.in);
			   }
		   }
	   }
	   
	   
	   
	   
	  
	   
	   
	   
	   
	   
   }
}
