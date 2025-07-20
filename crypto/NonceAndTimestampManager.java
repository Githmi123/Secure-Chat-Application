package crypto;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class NonceAndTimestampManager {
    private static final Set<String> usedNonces = new HashSet<>();

    public static boolean isFresh(String nonce, long timestamp){
        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > 2 * 60 * 1000) return false;
        synchronized (usedNonces) {
            if (usedNonces.contains(nonce)) return false;
            usedNonces.add(nonce);
        }
        return true;
    }

    public static String generateNonce(){
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }
}
