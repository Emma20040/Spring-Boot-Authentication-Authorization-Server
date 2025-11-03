package com.emma.Authentication.Services;

import com.emma.Authentication.DTOs.*;
import com.emma.Authentication.Repositories.UserRepository;
import com.emma.Authentication.UserModel.UserModel;
import jakarta.mail.MessagingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class AccountLinkingService {
    private static final Logger logger = LoggerFactory.getLogger(AccountLinkingService.class);

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthService authService;
    private final EmailServices emailServices;

    public AccountLinkingService(UserRepository userRepository,
                                 BCryptPasswordEncoder passwordEncoder,
                                @Lazy AuthService authService,
                                 EmailServices emailServices) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authService = authService;
        this.emailServices = emailServices;
    }


//      Connect Google account to currently authenticated user
    public LinkProviderResponse connectGoogleAccount(UUID userId, LinkGoogleAccountRequest request) {
        UserModel user = getUserByIdOrThrow(userId);

        verifyGoogleAccountNotAlreadyLinked(user);
        validatePasswordForManualUsers(user, request.password());

        TokenValidationResult validationResult = authService.validateGoogleToken(request.providerToken(), authService.maskEmail(user.getEmail()));

        if (!validationResult.isValid()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, validationResult.errorMessage());
        }

        verifyGoogleAccountNotLinkedToOtherUsers(validationResult.googleId(), userId);
        verifyEmailMatchesUserAccount(validationResult.email(), user.getEmail());

        return linkGoogleAccountToUser(user, validationResult.googleId());
    }


//      Add password authentication to Google-only account
    public LinkProviderResponse enablePasswordAuthentication(UUID userId, AddPasswordRequest request) {
        UserModel user = getUserByIdOrThrow(userId);

        verifyAccountDoesNotHavePassword(user);
        validateNewPassword(request.newPassword());

        return addPasswordToUserAccount(user, request.newPassword());
    }


//      Get user's current authentication methods
    public AuthMethodsResponse getUserAuthenticationMethods(UUID userId) {
        UserModel user = getUserByIdOrThrow(userId);

        return new AuthMethodsResponse(
                user.hasPassword(),
                user.hasGoogleAuth(),
                user.getAuthMethodCount(),
                user.getLinkedAt()
        );
    }

    // --------- HELPER METHODS ---------------
    private UserModel getUserByIdOrThrow(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private void verifyGoogleAccountNotAlreadyLinked(UserModel user) {
        if (user.hasGoogleAuth()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Account is already linked with Google");
        }
    }

    private void validatePasswordForManualUsers(UserModel user, String providedPassword) {
        if (user.hasPassword()) {
            if (providedPassword == null || providedPassword.trim().isEmpty()) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "Password required to link Google account");
            }
            if (!passwordEncoder.matches(providedPassword, user.getPassword())) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
            }
        }
    }

    private void verifyGoogleAccountNotLinkedToOtherUsers(String googleId, UUID currentUserId) {
        Optional<UserModel> existingUser = userRepository.findByGoogleId(googleId);
        if (existingUser.isPresent() && !existingUser.get().getId().equals(currentUserId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "This Google account is already linked to another user");
        }
    }

    private void verifyEmailMatchesUserAccount(String googleEmail, String userEmail) {
        if (!googleEmail.equalsIgnoreCase(userEmail)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Google account email does not match your account email");
        }
    }

    private LinkProviderResponse linkGoogleAccountToUser(UserModel user, String googleId) {
        user.setGoogleId(googleId);
        user.setLinkedAt(LocalDateTime.now());
        userRepository.save(user);

        logger.info("Successfully linked Google account to user: {}", user.getEmail());

        // Send account linked email
        sendAccountLinkedEmail(user.getEmail(), "Google");

        return LinkProviderResponse.success(
                "Google account linked successfully",
                "google",
                user.getLinkedAt()
        );
    }

    private void verifyAccountDoesNotHavePassword(UserModel user) {
        if (user.hasPassword()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Account already has a password");
        }
    }

    private void validateNewPassword(String newPassword) {
        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password cannot be empty");
        }
    }

    private LinkProviderResponse addPasswordToUserAccount(UserModel user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setLinkedAt(LocalDateTime.now());
        userRepository.save(user);

        logger.info("Successfully added password to Google user: {}", user.getEmail());

        // Send account linked email
        sendAccountLinkedEmail(user.getEmail(), "Password");

        return LinkProviderResponse.success(
                "Password added successfully",
                "password",
                user.getLinkedAt()
        );
    }


//     * Send email notification when account is linked
    private void sendAccountLinkedEmail(String email, String authMethod) {
        try {
            String subject = "New Login Method Added to Your Account";
            String content = "Hello,\n\n" +
                    "A new login method (" + authMethod + ") has been successfully added to your account.\n\n" +
                    "You can now use " + authMethod + " to sign in to your account.\n\n" +
                    "If this was not you, please contact support immediately.\n\n" +
                    "Best regards,\nThe Team";

            emailServices.sendEmail(email, subject, content);
            logger.info("Account linking notification sent to: {}", authService.maskEmail(email));

        } catch (MessagingException e) {
            logger.error("Failed to send account linking email to: {}", authService.maskEmail(email), e);
        }
    }
}