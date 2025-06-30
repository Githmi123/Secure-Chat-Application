import java.io.*;
import java.net.Socket;
// import java.util.Date;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final UserAuthManager authManager;
    private final SessionManager sessionManager;

    private String username;

    public ClientHandler(Socket socket, UserAuthManager authManager, SessionManager sessionManager) {
        this.clientSocket = socket;
        this.authManager = authManager;
        this.sessionManager = sessionManager;
    }

    @Override
    public void run() {
        try (
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))
        ) {
            writer.write("Enter command (register/login):\n");
            writer.flush();
            String command = reader.readLine();

            if ("register".equalsIgnoreCase(command)) {
                writer.write("Username:\n");
                writer.flush();
                String user = reader.readLine();

                writer.write("Password:\n");
                writer.flush();
                String pass = reader.readLine();

                writer.write("PublicKey:\n");
                writer.flush();
                String pubKey = reader.readLine();

                if (authManager.registerUser(user, pass, pubKey)) {
                    writer.write("Registered successfully.\n");
                } else {
                    writer.write("Registration failed (user exists).\n");
                }
                writer.flush();
            }

            if ("login".equalsIgnoreCase(command)) {
                writer.write("Username:\n");
                writer.flush();
                String user = reader.readLine();

                writer.write("Password:\n");
                writer.flush();
                String pass = reader.readLine();

                if (authManager.loginUser(user, pass)) {
                    String token = sessionManager.createSession(user);
                    this.username = user;
                    Logger.logEvent(clientSocket, user, "Login success. Token: " + token);
                    writer.write("Login success. SessionToken: " + token + "\n");
                } else {
                    Logger.logEvent(clientSocket, user, "Login failed.");
                    writer.write("Login failed.\n");
                }
                
                writer.flush();
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (username != null) {
                sessionManager.invalidateSession(username);
                Logger.logEvent(clientSocket, username, "Logged out.");
            }
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // private void logEvent(String event) {
    //     try (BufferedWriter bw = new BufferedWriter(new FileWriter("auth_log.txt", true))) {
    //         String clientIP = clientSocket.getInetAddress().getHostAddress();
    //         String logEntry = String.format("[%s] [IP: %s] [User: %s] %s",
    //                 new Date(), clientIP, username != null ? username : "unknown", event);
    //         bw.write(logEntry);
    //         bw.newLine();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
    // }
}
