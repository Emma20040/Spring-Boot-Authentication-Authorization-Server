package com.emma.Authentication.RateLimiter;

import com.emma.Authentication.Services.AuthService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
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
        tokenBucketScript = new DefaultRedisScript<>();
        tokenBucketScript.setScriptText(
                "local key = KEYS[1] " +
                        "local limit = tonumber(ARGV[1]) " +           // ARGV[1] = limit (burstTokens)
                        "local window = tonumber(ARGV[2]) " +          // ARGV[2] = timeWindowSeconds
                        "local refillTime = tonumber(ARGV[3]) " +      // ARGV[3] = currentTime in seconds
                        " " +
                        "local intervalPerPermit = window / limit " +  // Calculate interval between permits
                        "local burstTokens = limit " +                 // burstTokens same as limit
                        "local interval = window " +                   // interval same as window in seconds
                        " " +
                        "local bucket = redis.call('hgetall', key) " +
                        "local currentTokens " +
                        " " +
                        "if table.maxn(bucket) == 0 then " +
                        "    -- first check if bucket not exists, if yes, create a new one with full capacity " +
                        "    currentTokens = burstTokens " +
                        "    redis.call('hset', key, 'lastRefillTime', refillTime) " +
                        "elseif table.maxn(bucket) == 4 then " +
                        "    -- if bucket exists, first we try to refill the token bucket " +
                        "    local lastRefillTime, tokensRemaining = tonumber(bucket[2]), tonumber(bucket[4]) " +
                        " " +
                        "    if refillTime > lastRefillTime then " +
                        "        -- if refillTime larger than lastRefillTime, we should refill the token buckets " +
                        "        local intervalSinceLast = refillTime - lastRefillTime " +
                        "        if intervalSinceLast > interval then " +
                        "            currentTokens = burstTokens " +
                        "            redis.call('hset', key, 'lastRefillTime', refillTime) " +
                        "        else " +
                        "            local grantedTokens = math.floor(intervalSinceLast / intervalPerPermit) " +
                        "            if grantedTokens > 0 then " +
                        "                -- adjust lastRefillTime, we want shift left the refill time " +
                        "                local padMillis = math.fmod(intervalSinceLast, intervalPerPermit) " +
                        "                redis.call('hset', key, 'lastRefillTime', refillTime - padMillis) " +
                        "            end " +
                        "            currentTokens = math.min(grantedTokens + tokensRemaining, limit) " +
                        "        end " +
                        "    else " +
                        "        -- if not, it means some other operation later than this call made the call first " +
                        "        currentTokens = tokensRemaining " +
                        "    end " +
                        "end " +
                        " " +
                        "assert(currentTokens >= 0) " +
                        " " +
                        "local allowed = 0 " +
                        "local remaining = 0 " +
                        "local retryAfter = 0 " +
                        " " +
                        "if currentTokens == 0 then " +
                        "    -- we didn't consume any keys " +
                        "    redis.call('hset', key, 'tokensRemaining', currentTokens) " +
                        "    allowed = 0 " +
                        "    remaining = 0 " +
                        "    -- Calculate retry after time " +
                        "    retryAfter = intervalPerPermit " +
                        "else " +
                        "    redis.call('hset', key, 'tokensRemaining', currentTokens - 1) " +
                        "    allowed = 1 " +
                        "    remaining = currentTokens - 1 " +
                        "end " +
                        " " +
                        "-- Set expiration time for the key " +
                        "redis.call('expire', key, window) " +
                        " " +
                        "return {allowed, remaining, retryAfter}"

        );
        tokenBucketScript.setResultType(List.class);
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