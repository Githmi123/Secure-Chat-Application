package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Date;

public class Logger {
    private static final String LOG_FILE = "auth_log.txt";

    public static void logEvent(Socket socket, String username, String eventType) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            String ip = socket.getInetAddress().getHostAddress();
            String timestamp = new Date().toString();
            String baseEntry = String.format("[%s] [IP: %s] [User: %s] %s", timestamp, ip, username, eventType);

            String prevHash = getLastLogHash();
            String currentHash = sha256(prevHash + baseEntry);

            String fullEntry = baseEntry + " HASH=" + currentHash;
            writer.write(fullEntry);
            writer.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getLastLogHash() {
        File file = new File(LOG_FILE);
        if (!file.exists()) return "GENESIS";

        String lastLine = "";
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lastLine = line;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        int idx = lastLine.lastIndexOf("HASH=");
        if (idx != -1) {
            return lastLine.substring(idx + 5).trim();
        } else {
            return "GENESIS";
        }
    }

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                String hexChar = Integer.toHexString(0xff & b);
                if (hexChar.length() == 1) hex.append('0');
                hex.append(hexChar);
            }
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
