package com.emma.Authentication.Utils;


import com.emma.Authentication.Configs.JwtConfig;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class JwtActions {
    @Value("${jwt.expiration:300000}")
    private Long jwtExpiration;

    private final JwtConfig jwtConfig;

    public JwtActions(JwtConfig jwtConfig) {

        this.jwtConfig = jwtConfig;
    }

    public String jwtCreate(UUID id, String email ,String username, String role) {
        var now = Instant.now();
        var claims = JwtClaimsSet.builder()
                .issuer("Authentication-server")
                .subject(id.toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(jwtExpiration))
                .claim("email", email != null ? email : "")
                .claim("username", username != null ? username : "")
                .claim("role", role)
                .build();
        return jwtConfig.jwtEncoder().encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }


    //    decodes jwt
    public Jwt decodeToken(String token) {
        return jwtConfig.jwtDecoder().decode(token);
    }
}
