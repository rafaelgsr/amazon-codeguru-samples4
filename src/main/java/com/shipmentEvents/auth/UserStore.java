package com.shipmentEvents.auth;

import java.util.HashMap;
import java.util.Map;
import org.mindrot.jbcrypt.BCrypt;

public class UserStore {

    private static final Map<String, String> USERS = new HashMap<>();

    static {
        // Demo users with bcrypt-hashed passwords
        // admin / admin123
        USERS.put("admin", BCrypt.hashpw("admin123", BCrypt.gensalt()));
        // user / password
        USERS.put("user", BCrypt.hashpw("password", BCrypt.gensalt()));
    }

    public boolean authenticate(String username, String password) {
        if (username == null || password == null) {
            return false;
        }
        String storedHash = USERS.get(username);
        if (storedHash == null) {
            return false;
        }
        return BCrypt.checkpw(password, storedHash);
    }
}
