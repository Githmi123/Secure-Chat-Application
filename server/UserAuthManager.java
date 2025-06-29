import java.io.*;
import java.util.*;
import org.bouncycastle.crypto.generators.BCrypt;
import java.security.SecureRandom;

public class UserAuthManager {
    private static final String USER_FILE = "users.txt";

    public boolean registerUser(String username, String password, String publicKey) {
        if (userExists(username)) return false;

        byte[] salt = generateSalt();
        byte[] hashed = BCrypt.generate(password.getBytes(), salt, 12);
        String encoded = Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hashed);

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(USER_FILE, true))) {
            bw.write(username + ":" + encoded + ":" + publicKey);
            bw.newLine();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean loginUser(String username, String password) {
        try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 4);
                if (parts[0].equals(username)) {
                    byte[] salt = Base64.getDecoder().decode(parts[1]);
                    byte[] storedHash = Base64.getDecoder().decode(parts[2]);
                    byte[] providedHash = BCrypt.generate(password.getBytes(), salt, 12);
                    return Arrays.equals(storedHash, providedHash);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public String getPublicKey(String username) {
        try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 4);
                if (parts[0].equals(username)) return parts[3];
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private boolean userExists(String username) {
        try (BufferedReader br = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(username + ":")) return true;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
}
