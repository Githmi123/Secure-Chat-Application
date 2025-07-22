package server;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
    private final Map<String, String> sessionTokens = new ConcurrentHashMap<>(); // username -> token

    public String createSession(String username) {
        String token = UUID.randomUUID().toString();
        sessionTokens.put(username, token);
        return token;
    }

    public boolean isValidSession(String username, String token) {
        return token.equals(sessionTokens.get(username));
    }

    public void invalidateSession(String username) {
        sessionTokens.remove(username);
    }

    public Set<String> getOnlineUsers() {
        return sessionTokens.keySet();
    }
}
