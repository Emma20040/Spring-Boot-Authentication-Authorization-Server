package com.emma.Authentication.RateLimiter;

import com.emma.Authentication.Services.AuthService;
import com.emma.Authentication.RateLimiter.RateLimit;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

@Aspect
@Component
public class RateLimitAspect {

    @Autowired
    private RedisRateLimiter redisRateLimiter;

    @Autowired
    private HttpServletRequest httpServletRequest;

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Around("@annotation(com.emma.Authentication.RateLimiter.RateLimit)")
    public Object rateLimit(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        RateLimit rateLimit = method.getAnnotation(RateLimit.class);

        String redisKey = buildRedisKey(rateLimit, method);
        // Add debug logging
        logger.info("Rate limit check - Key: {}, Limit: {}, Window: {}s",
                redisKey, rateLimit.limit(), rateLimit.timeWindowSeconds());

        RedisRateLimiter.RateLimitResult result = redisRateLimiter.isAllowed(
                redisKey,
                rateLimit.limit(),
                rateLimit.timeWindowSeconds()
        );

        logger.info("Rate limit result - Allowed: {}, Remaining: {}, RetryAfter: {}",
                result.isAllowed(), result.getRemaining(), result.getRetryAfter());

        if (!result.isAllowed()) {
            logger.warn("Rate limit exceeded for key: {}", redisKey);
            throw new RateLimitExceedException(
                    String.format("Too Many Requests. Try again in %d seconds.", result.getRetryAfter())
            );
        }

        return joinPoint.proceed();
    }

    private String buildRedisKey(RateLimit rateLimit, Method method) {
        String baseKey = "ratelimit:" + method.getName();

        if (rateLimit.type() == RateLimitType.USERID) {
            String userId = getCurrentUserId();
            return baseKey + ":user:" + userId;
        } else {
            String clientIp = getClientIp();
            return baseKey + ":ip:" + clientIp;
        }
    }

    private String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                return ((UserDetails) principal).getUsername();
            } else {
                return authentication.getName();
            }
        }
        return "anonymous";
    }

    private String getClientIp() {
        String xfHeader = httpServletRequest.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0].trim();
        }
        return httpServletRequest.getRemoteAddr();
    }
}
