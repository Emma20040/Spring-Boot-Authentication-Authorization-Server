package com.emma.Authentication.Services;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RedisTemplate<String, String> redisTemplate;

    // Configurable expiration (7 days default)
    @Value("${app.refresh.token.expiration}")
    private long refreshTokenExpiration;

    // Configurable Redis key prefixes
    @Value("${app.redis.prefix.user-refresh:refresh:user:}")
    private String userRefreshKeyPrefix;

    @Value("${app.redis.prefix.token-user:refresh:token:}")
    private String tokenUserKeyPrefix;

    public RefreshTokenService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


//      Generate and store a refresh token for a user

    public String generateAndStoreRefreshToken(String userId) {
        String refreshToken = UUID.randomUUID().toString();

        // Store token  userId mapping
        String tokenKey = tokenUserKeyPrefix + refreshToken;
        redisTemplate.opsForValue().set(tokenKey, userId, Duration.ofSeconds(refreshTokenExpiration));

        // Add token to user's set
        String userKey = userRefreshKeyPrefix + userId;
        redisTemplate.opsForSet().add(userKey, refreshToken);
        redisTemplate.expire(userKey, Duration.ofSeconds(refreshTokenExpiration));

        logger.info("Generated refresh token for user: {}, token: {}", userId, maskToken(refreshToken));
        return refreshToken;
    }


//      Validate refresh token and return userId

    public String validateAndGetUserId(String refreshToken) {
        String tokenKey = tokenUserKeyPrefix + refreshToken;
        String userId = redisTemplate.opsForValue().get(tokenKey);

        if (userId == null) {
            logger.warn("Invalid or expired refresh token attempt: {}", maskToken(refreshToken));
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        logger.debug("Valid refresh token for user: {}, token: {}", userId, maskToken(refreshToken));
        return userId;
    }


//      Invalidate a single refresh token (logout from current device only)

    public void invalidateRefreshToken(String refreshToken) {
        String tokenKey = tokenUserKeyPrefix + refreshToken;
        String userId = redisTemplate.opsForValue().get(tokenKey);

        if (userId != null) {
            // Remove from user's set
            String userKey = userRefreshKeyPrefix + userId;
            redisTemplate.opsForSet().remove(userKey, refreshToken);

            logger.info("Invalidated refresh token for user: {}, token: {}", userId, maskToken(refreshToken));
        } else {
            logger.warn("Attempted to invalidate non-existent refresh token: {}", maskToken(refreshToken));
        }

        // Delete token  user mapping
        redisTemplate.delete(tokenKey);
    }


//      Invalidate all refresh tokens for a user (logout from all devices) which will be used for admin endpionts

    public void invalidateAllForUser(String userId) {
        String userKey = userRefreshKeyPrefix + userId;
        Set<String> tokens = redisTemplate.opsForSet().members(userKey);

        if (tokens != null && !tokens.isEmpty()) {
            for (String token : tokens) {
                String tokenKey = tokenUserKeyPrefix + token;
                redisTemplate.delete(tokenKey);
            }
            logger.info("Invalidated all {} refresh tokens for user: {}", tokens.size(), userId);
        } else {
            logger.debug("No refresh tokens found to invalidate for user: {}", userId);
        }

        redisTemplate.delete(userKey);
    }



//      Check if refresh token is valid

    public boolean isValidRefreshToken(String refreshToken) {
        String tokenKey = tokenUserKeyPrefix + refreshToken;
        boolean isValid = redisTemplate.hasKey(tokenKey);

        logger.debug("Refresh token validation check: {} - valid: {}", maskToken(refreshToken), isValid);
        return isValid;
    }


//      Rotate refresh token: invalidate old one, issue new one

    public String rotateRefreshToken(String oldRefreshToken) {
        String userId = validateAndGetUserId(oldRefreshToken);
        invalidateRefreshToken(oldRefreshToken);
        String newRefreshToken = generateAndStoreRefreshToken(userId);

        logger.info("Rotated refresh token for user: {}, old: {}, new: {}",
                userId, maskToken(oldRefreshToken), maskToken(newRefreshToken));
        return newRefreshToken;
    }


//      Get number of active refresh tokens for a user

    public Long getActiveTokenCount(String userId) {
        String userKey = userRefreshKeyPrefix + userId;
        Long count = redisTemplate.opsForSet().size(userKey);
        return count != null ? count : 0L;
    }


//      Mask token for logging (security)

    private String maskToken(String token) {
        if (token == null || token.length() <= 8) {
            return "***";
        }
        return token.substring(0, 4) + "..." + token.substring(token.length() - 4);
    }
}