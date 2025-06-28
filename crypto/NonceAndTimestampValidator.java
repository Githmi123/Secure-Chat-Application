package crypto;

import java.util.HashSet;
import java.util.Set;

public class NonceAndTimestampValidator {
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
}
