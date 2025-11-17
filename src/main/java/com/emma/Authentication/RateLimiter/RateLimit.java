package com.emma.Authentication.RateLimiter;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {
    int limit();
    int timeWindowSeconds();
    RateLimitType type() default RateLimitType.IP;
}
