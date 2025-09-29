package com.emma.Authentication.Services;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;
import java.util.Map;

@Service
public class JwtBlacklistService {
    // Thread-safe map to store blacklisted tokens and their expiration times
    private final Map<String, Instant> jwtBlacklistedTokens = new ConcurrentHashMap<>();

    //    Adds a token to the blacklist with its expiration time
    public void blacklistToken(String token, Instant expirationTime) {
        jwtBlacklistedTokens.put(token, expirationTime);
    }


    public boolean isTokenBlacklisted(String token) {
        return jwtBlacklistedTokens.containsKey(token);
    }

    //    Scheduled task to clean up expired tokens from the blacklist
    @Scheduled(fixedDelay = 10000) // Run every 10s (10000ms) seconds
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        // automatically Remove tokens that have already expired
        jwtBlacklistedTokens.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }

}