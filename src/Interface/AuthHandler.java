package Interface;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Scanner;

public class AuthHandler {

	public static String login(Scanner scanner,PrintWriter out,BufferedReader in) throws IOException {
		System.out.print("Username:");
		String username =scanner.nextLine();
		System.out.print("Password:");
		String password =scanner.nextLine();
		
		
		out.println("LOGIN:" + username + ":" + password);
        String response = in.readLine();
        
		if (response !=null && response.startsWith("SUCCESS")) {
			return response.split(":")[1]; //return session token
		}
		else {
			System.out.println("Login Failed:"+response);
			return null;
		}
	}

	public static String register(Scanner scanner,PrintWriter out,BufferedReader in) throws IOException {
		System.out.print("Username:");
		String username =scanner.nextLine();
		System.out.print("Password:");
		String password =scanner.nextLine();
		
		out.println("REGISTER:"+username+":"+password);
		String response =in.readLine();
		
		if (response !=null && response.equals("REGISTERED")) {
			System.out.println("Registration successful.PLease login.");
			return login(scanner,out,in);
		}
		else {
			System.out.println("Registration failed:"+response);
			return null;
		}
		
	}
}
