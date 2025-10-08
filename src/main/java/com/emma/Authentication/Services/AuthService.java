package com.emma.Authentication.Services;

import com.emma.Authentication.DTOs.LoginResponse;
import com.emma.Authentication.Repositories.UserRepository;
import com.emma.Authentication.UserModel.UserModel;
import com.emma.Authentication.Utils.JwtActions;
import jakarta.mail.MessagingException;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static com.emma.Authentication.enums.Roles.USER;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Service
public class AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final EmailServices emailServices;
    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtActions jwtActions;

    private final JwtBlacklistService jwtBlacklistService;


    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${app.verification.token.expiration:3600}") // 1 hour default
    private long verificationTokenExpiration;

    private final String PRE_VERIFICATION_USER_KEY = "pre_verification_user:";

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder,
                       EmailServices emailServices, RedisTemplate<String, Object> redisTemplate,

                       RefreshTokenService refreshTokenService, JwtActions jwtActions,
                       JwtBlacklistService jwtBlacklistService) {

                       RefreshTokenService refreshTokenService, JwtActions jwtActions) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailServices = emailServices;
        this.redisTemplate = redisTemplate;
        this.refreshTokenService= refreshTokenService;
        this.jwtActions= jwtActions;

        this.jwtBlacklistService = jwtBlacklistService;

    }

//    get user by username
    private Optional<UserModel> findUserByUsername(String username) {

        return userRepository.findByUsername(username);
    }

//    get user by email only
    private Optional<UserModel> findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

//    grt user either by username or email
    private Optional<UserModel> findUserByEmailOrUsername(String emailOrUsername){
        Optional<UserModel> findByEmail = findUserByEmail((emailOrUsername));
        if (findByEmail.isPresent()){
            return findByEmail;
        }

        return findUserByUsername(emailOrUsername);
    }

    // Find pending verification by email in redis
    private String findPendingVerificationByEmail(String email) {
        String pattern = PRE_VERIFICATION_USER_KEY + "*";
        var keys = redisTemplate.keys(pattern);

        if (keys != null) {
            for (String key : keys) {
                UserModel user = (UserModel) redisTemplate.opsForValue().get(key);
                if (user != null && email.equals(user.getEmail())) {
                    // Extract token from key (remove the prefix)
                    return key.substring(PRE_VERIFICATION_USER_KEY.length());
                }
            }
        }
        return null;
    }


//    verify password during login
    private boolean verifyPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }



//    manual signup (register without using google)
    public void manualSignup(String email, String username, String password) {
//        check if another user already has that email
        if (findUserByEmail(email).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already exists");
        }

//        checks if that username is already present in the db
        if (findUserByUsername(username).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "username is already taken by another user");
        }

        // Check if there's already a pending verification for this email and delete the token
        String existingToken = findPendingVerificationByEmail(email);
        if (existingToken != null) {
            // Delete the old token
            redisTemplate.delete(PRE_VERIFICATION_USER_KEY + existingToken);
        }


//        Hash the user password
        var hashedPassword = passwordEncoder.encode(password);

        // Create pre-verification user
        UserModel preVerificationUser = new UserModel();
        preVerificationUser.setEmail(email);
        preVerificationUser.setUsername(username);
        preVerificationUser.setEnable(false);
        preVerificationUser.setPassword(hashedPassword);
        preVerificationUser.setRole(USER);

//          Generate verification token and send to user email for account verification
        String verificationToken = UUID.randomUUID().toString();
        String baseUrl = "http://localhost:8080/api/auth/verify-email?token=";
        String verificationLink = baseUrl + verificationToken;

        // Store verifiction token in Redis with expiration
        String redisKey = PRE_VERIFICATION_USER_KEY + verificationToken;
        redisTemplate.opsForValue().set(redisKey, preVerificationUser, Duration.ofSeconds(verificationTokenExpiration));

//        send email
        try {
            emailServices.sendEmail(email, "Verify your email Click the link below to verify your email: ", verificationLink);

        } catch (MessagingException e) {
            // Clean up if email fails
            redisTemplate.delete(redisKey);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to send verification email. Please try again.");
        }

    }


    // Verify email
    public void verifyEmail(String token) {
        String redisKey = PRE_VERIFICATION_USER_KEY + token;
        UserModel preVerificationUser = (UserModel) redisTemplate.opsForValue().get(redisKey);

        if (preVerificationUser == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired verification token");
        }

        // Double-check if user already exists
        if (findUserByEmail(preVerificationUser.getEmail()).isPresent() ||
                findUserByUsername(preVerificationUser.getUsername()).isPresent()) {
            redisTemplate.delete(redisKey);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User already exists");
        }

        // Save to database
        preVerificationUser.setEnable(true);
        userRepository.save(preVerificationUser);

        // Clean up Redis
        redisTemplate.delete(redisKey);
    }



    // Resend verification token
    public void resendVerification(String email) {
        // Check if user already exists in database
        if (findUserByEmail(email).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already verified and registered");
        }

        // Find existing pending verification
        String existingToken = findPendingVerificationByEmail(email);
        if (existingToken == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "No pending registration found for this email. Please register first.");
        }

        // Get the user data from existing token
        String oldRedisKey = PRE_VERIFICATION_USER_KEY + existingToken;
        UserModel preVerificationUser = (UserModel) redisTemplate.opsForValue().get(oldRedisKey);

        if (preVerificationUser == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Pending registration expired. Please register again.");
        }

        // Generate new token
        String newVerificationToken = UUID.randomUUID().toString();
        String newRedisKey = PRE_VERIFICATION_USER_KEY + newVerificationToken;
        String verificationLink = "http://localhost:8080/api/auth/verify-email?token=" + newVerificationToken;

        // Store with new token
        redisTemplate.opsForValue().set(newRedisKey, preVerificationUser,
                Duration.ofSeconds(verificationTokenExpiration));

        // Delete old token
        redisTemplate.delete(oldRedisKey);

        // Send new verification email
        try {
            emailServices.sendEmail(email, "Verify your email you can request for another link",
                    "Click the link below to verify your email: " + verificationLink);
        } catch (MessagingException e) {
            // Clean up if email fails
            redisTemplate.delete(newRedisKey);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to send verification email. Please try again.");
        }
    }



//    manual Login
    public LoginResponse manualLogin(String emailOrUsername, String password) {
        var user = findUserByEmailOrUsername(emailOrUsername)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Invalid login credentials"));

        if (!user.isEnable()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email not verified verify email and try again");
        }

        if (!verifyPassword(password, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid login credentials");
        }

        // Generate JWT
        String jwtToken = jwtActions.jwtCreate(user.getId(), user.getEmail(), user.getUsername(), user.getRole().toString());

        // Generate and store refresh token
        String refreshToken = refreshTokenService.generateAndStoreRefreshToken(user.getId().toString());

        return new LoginResponse(jwtToken, refreshToken, "Login successful");
    }


    // refreshTokens method:
    public LoginResponse refreshTokens(String refreshToken) {
        // Validate refresh token and get user ID
        String userId = refreshTokenService.validateAndGetUserId(refreshToken);

        // Get user from database
        UserModel user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // Generate new JWT using JwtActions
        String newJwt = jwtActions.jwtCreate(user.getId(), user.getEmail(),
                user.getUsername(), user.getRole().toString());

        // Rotate refresh token (invalidate old, generate new)
        String newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);

        return new LoginResponse(newJwt, newRefreshToken, "Tokens refreshed successfully");
    }


    // Logout - single device only
    public void logoutSingleDevice(String jwtToken, String refreshToken) {
        try {
            // Extract user info from JWT for logging
            var jwt = jwtActions.decodeToken(jwtToken);
            String userId = jwt.getSubject();

//            verify refresh token ownership
            if (!refreshTokenService.isRefreshTokenValidForUser(refreshToken, userId)) {
                logger.warn("Attempt to invalidate refresh token {} for user {} failed: token does not belong to user.",
                        refreshToken, userId);
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid refresh token.");
            }

            // Blacklist the JWT
            Instant expiration = jwt.getExpiresAt();
            jwtBlacklistService.blacklistToken(jwtToken, expiration);

            // Invalidate the specific refresh token (single device)
            refreshTokenService.invalidateRefreshToken(refreshToken);

            logger.info("User {} logged out from single device. JWT blacklisted and refresh token invalidated.", userId);

        } catch (Exception e) {
            logger.error("Error during single device logout", e);
            if (e instanceof ResponseStatusException){
                throw e;
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token");
        }
    }


    // Logout from all devices
    public void logoutAllDevices(String jwtToken) {
        try {
            // Extract user ID from JWT
            var jwt = jwtActions.decodeToken(jwtToken);
            String userId = jwt.getSubject();

            // Blacklist the current JWT
            Instant expiration = jwt.getExpiresAt();
            jwtBlacklistService.blacklistToken(jwtToken, expiration);

            // Invalidate ALL refresh tokens for this user
            refreshTokenService.invalidateAllForUser(userId);

            logger.info("User {} logged out from all devices. All sessions terminated.", userId);

        } catch (Exception e) {
            logger.error("Error during logout all devices", e);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token");
        }
    }


}
