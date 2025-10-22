package com.emma.Authentication.Configs;

import com.emma.Authentication.Services.JwtValidationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtConfig jwtConfig;
    private final JwtValidationService jwtValidationService;

    public SecurityConfig(JwtConfig jwtConfig, JwtValidationService jwtValidationService) {
        this.jwtConfig = jwtConfig;
        this.jwtValidationService = jwtValidationService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.requestMatchers(HttpMethod.POST, "/user/register").permitAll()
                        .requestMatchers("/").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/verify-email").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/resend-verification").permitAll()
                        .requestMatchers(HttpMethod.POST, "api/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "api/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.POST, "api/auth/google/signup").permitAll()

                        .requestMatchers(HttpMethod.POST, "api/auth/logout").authenticated()
                        .requestMatchers(HttpMethod.POST, "api/auth/logout-all").authenticated()



                        .anyRequest().authenticated())
                .oauth2Login(withDefaults())
                .oauth2ResourceServer(config -> config.jwt(jwt -> jwt.decoder(jwtConfig.jwtDecoder())));

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("role");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
