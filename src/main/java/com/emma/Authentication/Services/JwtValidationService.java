package com.emma.Authentication.Services;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

@Service
public class JwtValidationService {
    private final JwtDecoder jwtDecoder;
    private final JwtBlacklistService jwtBlacklistService;

    public JwtValidationService(JwtDecoder jwtDecoder, JwtBlacklistService jwtBlacklistService) {
        this.jwtDecoder = jwtDecoder;
        this.jwtBlacklistService = jwtBlacklistService;
    }

    //    Validates a JWT token by checking: signature validity, expiration and Blacklist status
    public boolean isValidToken(String token) {
        try {

//// Decode and validate token signature/expiration
            Jwt jwt = jwtDecoder.decode(token);

            // Check if token is blacklisted
            return !jwtBlacklistService.isTokenBlacklisted(token);
        } catch (JwtException e) {
            return false;
        }
    }


//      Decodes a JWT token without blacklist validation

    public Jwt decodeToken(String token) {
        return jwtDecoder.decode(token);
    }
}
