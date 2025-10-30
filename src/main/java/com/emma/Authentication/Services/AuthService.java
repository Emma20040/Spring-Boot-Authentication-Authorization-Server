package com.emma.Authentication.Services;


import com.emma.Authentication.DTOs.*;
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
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.emma.Authentication.enums.Roles.USER;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.emma.Authentication.Repositories.UserRepository;
import com.emma.Authentication.UserModel.UserModel;
import com.emma.Authentication.Utils.JwtActions;


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
    @Value("${google.client.id}")
    private String googleClientId;

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder,
                       EmailServices emailServices, RedisTemplate<String, Object> redisTemplate,

                       RefreshTokenService refreshTokenService, JwtActions jwtActions,
                       JwtBlacklistService jwtBlacklistService) {


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

    //    get user by googleId
    private Optional<UserModel> findByGoogleId(String googleId) {
        return userRepository.findByGoogleId(googleId);
    }

    //    grt user either by username or email
    private Optional<UserModel> findUserByEmailOrUsername(String emailOrUsername) {
        Optional<UserModel> findByEmail = findUserByEmail((emailOrUsername));
        if (findByEmail.isPresent()) {
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
//               security check: prevent users from submitting empyt password field
        if(password ==null || password.trim().isEmpty()){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password is null ");
        }

        var user = findUserByEmailOrUsername(emailOrUsername)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Invalid login credentials"));

//        SECURITY CHECK: checks if user is registered with google (and has no password) prevent server from processing null password fields
        if (user.getPassword() == null) {
            String message = "This account doesn't support password login. ";

            if (user.getGoogleId() != null) {
                message += "Please sign in with Google.";
            } else {
                message += "Please use your original sign-in method.";
            }

            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
        }

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
            if (e instanceof ResponseStatusException) {
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


    // --------- GOOGLE OAUTH2  -----------

    // Google signup - extract only email and googleId
    public GoogleSignupResponse googleSignup(String email, String googleId) {
        // Mask sensitive data in logs
        String maskedEmail = maskEmail(email);
        logger.info("Processing Google signup for email: {}, googleId: [REDACTED]", maskedEmail);

        //  Validate Google ID token
        TokenValidationResult validationResult = validateGoogleToken(googleId, maskedEmail);
        if (!validationResult.isValid()) {
            return validationResult.getErrorResponse();
        }

        // Use the validated email and googleId from the token
        String verifiedEmail = validationResult.email();
        String verifiedGoogleId = validationResult.googleId();

        //  Check if user already exists with this googleId
        GoogleSignupResponse existingUserResponse = checkUserExistsWithGoogleId(verifiedGoogleId);
        if (existingUserResponse != null) {
            return existingUserResponse;
        }

        // Check if user already exists with this email
        Optional<UserModel> existingUserByEmail = findUserByEmail(verifiedEmail);
        if (existingUserByEmail.isPresent()) {
            logger.warn("Google signup attempted with existing email: {}", maskedEmail);
            return GoogleSignupResponse.builder()
                    .message("Account already exists with this email. Try logging in instead.")
                    .success(false)
                    .requiresLogin(true)
                    .build();
        }

        // Create new user with only email and googleId
        return createUserWithGoogle(verifiedEmail, verifiedGoogleId);
    }


    // Create user with only email and googleId and automatically login
    private GoogleSignupResponse createUserWithGoogle(String email, String googleId) {
        try {
            UserModel newUser = new UserModel();
            newUser.setEmail(email);
            newUser.setGoogleId(googleId);
            newUser.setEnable(true); // Google users are auto-verified
            newUser.setRole(USER);   // Default role is USER
            // Username and password are null for Google users

            UserModel savedUser = userRepository.save(newUser);
            logger.info("Successfully created new user via Google signup: {}", maskEmail(email));

            // Generate JWT and refresh token for automatic login
            String jwtToken = jwtActions.jwtCreate(savedUser.getId(), savedUser.getEmail(),
                    savedUser.getUsername(), savedUser.getRole().toString());
            String refreshToken = refreshTokenService.generateAndStoreRefreshToken(savedUser.getId().toString());

            // Send welcome email
            sendWelcomeEmail(email);

            return GoogleSignupResponse.builder()
                    .message("Google signup successful! Welcome to our platform.")
                    .success(true)
                    .userId(savedUser.getId().toString())
                    .jwtToken(jwtToken)
                    .refreshToken(refreshToken)
                    .requiresLogin(false)
                    .build();

        } catch (Exception e) {
            logger.error("Error creating user with Google signup for email: {}", maskEmail(email), e);
            return GoogleSignupResponse.builder()
                    .message("Failed to complete Google signup. Please try again.")
                    .success(false)
                    .requiresLogin(false)
                    .build();
        }
    }


//    method for existing users with googleId to login
    public GoogleLoginResponse googleLogin(String email, String googleId){
//        masked email
        String maskedEmail = maskEmail(email);
        logger.info("Processing Google login for email: {}, googleId: [REDACTED]", maskedEmail);

//        verify googleId token
        TokenValidationResult validationResult = validateGoogleToken(googleId, maskedEmail);
        if(!validationResult.isValid()){
            return  GoogleLoginResponse.builder()
                    .message(validationResult.getErrorResponse().message())
                    .success(false)
                    .build();
        }

//        get validated email and googleId from token
        String verifiedEmail = validationResult.email();
        String verifiedGoogleId = validationResult.googleId();

//        find user by googleId
        Optional<UserModel> existingUserByGoogleId = findByGoogleId(verifiedGoogleId);
        if (existingUserByGoogleId.isPresent()) {
            UserModel user = existingUserByGoogleId.get();
            return generateGoogleLoginResponse(user, "Google login successful!");
        }

//        if no goggleId is found
        logger.warn("Google login attempted for non-Google user: {}", maskedEmail);
        return GoogleLoginResponse.builder()
                .message("No Google account found. Please sign up with Google first or use manual login.")
                .success(false)
                .build();
    }


    // Validate Google token
    private TokenValidationResult validateGoogleToken(String googleId, String maskedEmail) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new JacksonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(googleId);
            if (idToken == null) {
                logger.warn("Invalid Google ID token for email: {}", maskedEmail);
                return TokenValidationResult.invalid("Invalid Google authentication token.");
            }

            Payload payload = idToken.getPayload();
            String verifiedEmail = (String) payload.get("email");
            String verifiedGoogleId = payload.getSubject(); // Securely extracted Google user ID

            return TokenValidationResult.valid(verifiedEmail, verifiedGoogleId);

        } catch (Exception e) {
            logger.error("Google token verification failed for email: {}", maskedEmail, e);
            return TokenValidationResult.invalid("Failed to verify Google token. Please try again.");
        }
    }


    // Check if user exists with googleId
    private GoogleSignupResponse checkUserExistsWithGoogleId(String googleId) {
        Optional<UserModel> existingUserByGoogleId = findByGoogleId(googleId);
        if (existingUserByGoogleId.isPresent()) {
            logger.warn("Google signup attempted with existing googleId: {}", googleId);
            return GoogleSignupResponse.builder()
                    .message("User already exists with this Google account. Please login.")
                    .success(false)
                    .requiresLogin(true)
                    .build();
        }
        return null;
    }




    // Send welcome email for Google users
    private void sendWelcomeEmail(String email) {
        try {
            String subject = "Welcome to Our Platform!";
            String content = "Hello,\n\n" +
                    "Welcome to our platform! Your account has been successfully created " +
                    "using Google authentication.\n\n" +
                    "You can now login to your account using Google Sign-In.\n\n" +
                    "Best regards,\nThe Team";

            emailServices.sendEmail(email, subject, content);
            logger.info("Welcome email sent to: {}", maskEmail(email));

        } catch (MessagingException e) {
            logger.error("Failed to send welcome email to: {}", maskEmail(email), e);

        }
    }

    //helper method Extract Google user info from OAuth2 attributes
    public GoogleUserInfo extractGoogleUserInfo(Map<String, Object> attributes) {
        return new GoogleUserInfo(
                (String) attributes.get("email"),
                (String) attributes.get("sub")
        );
    }


    // Helper method to mask email in logs
    private String maskEmail(String email) {
        return (email != null && email.contains("@")) ? email.split("@")[0] + "@***" : "unknown";
    }


    // Helper method to generate login response for user that logn with google
    private GoogleLoginResponse generateGoogleLoginResponse(UserModel user, String message){
        try{
//            generate refresh and jwt token
            String jwtToken =jwtActions.jwtCreate(user.getId(), user.getEmail(), user.getUsername(), user.getRole().toString());
            String refreshToken = refreshTokenService.generateAndStoreRefreshToken(user.getId().toString());

            logger.info("Successful Google login for user: {}", maskEmail(user.getEmail()));

            return GoogleLoginResponse.builder()
                    .message(message)
                    .success(true)
                    .userId(user.getId().toString())
                    .jwtToken(jwtToken)
                    .refreshToken(refreshToken)
                    .build();

        } catch (Exception e){
            logger.info("Error generating tokens for Google login: {}", maskEmail(user.getEmail()));

            return GoogleLoginResponse.builder()
                    .message("Login successful but failed to generate tokens. Please try again.")
                    .success(false)
                    .build();
        }
    }



}



