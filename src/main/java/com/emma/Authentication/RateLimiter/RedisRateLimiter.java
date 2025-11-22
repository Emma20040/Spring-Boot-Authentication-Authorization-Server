package com.emma.Authentication.RateLimiter;

import com.emma.Authentication.Services.AuthService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;
import java.util.List;

@Service
public class RedisRateLimiter {

    @Autowired
    private StringRedisTemplate redisTemplate;
    private DefaultRedisScript<List> tokenBucketScript;

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    // Lua script for token bucket algorithm
    @PostConstruct
    public void init() {
        try {
            tokenBucketScript = new DefaultRedisScript<>();
            tokenBucketScript.setLocation(new ClassPathResource("token_bucket_rate_limiter.lua"));
            tokenBucketScript.setResultType(List.class);
            logger.info("Lua script loaded successfully from file");
        } catch (Exception e) {
            logger.error("Failed to load Lua script from file", e);
            throw new RuntimeException("Failed to initialize rate limiter", e);
        }
    }



    public RateLimitResult isAllowed(String key, int limit, int timeWindowSeconds) {
        long currentTime = System.currentTimeMillis() / 1000;

        List<Long> result = redisTemplate.execute(
                tokenBucketScript,
                Arrays.asList(key),
                String.valueOf(limit),
                String.valueOf(timeWindowSeconds),
                String.valueOf(currentTime)
        );

        if (result == null || result.size() < 3) {
            return new RateLimitResult(false, 0, 0);
        }

        boolean allowed = result.get(0) == 1;
        long remaining = result.get(1);
        long retryAfter = result.get(2);

        return new RateLimitResult(allowed, remaining, retryAfter);
    }

    public static class RateLimitResult {
        private final boolean allowed;
        private final long remaining;
        private final long retryAfter;

        public RateLimitResult(boolean allowed, long remaining, long retryAfter) {
            this.allowed = allowed;
            this.remaining = remaining;
            this.retryAfter = retryAfter;
        }

        public boolean isAllowed() { return allowed; }
        public long getRemaining() { return remaining; }
        public long getRetryAfter() { return retryAfter; }
    }
}