package com.emma.Authentication.Controllers;

import com.emma.Authentication.DTOs.*;
import com.emma.Authentication.Services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

//    ---------- SIGNUP ------------

    // Register endpoint
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> registerUser(@RequestBody @Valid SignupDto signupDto) {
        authService.manualSignup(signupDto.email(), signupDto.username(), signupDto.password());
        return ResponseEntity.ok(Map.of("message", " verify email to complete registration.  Verification email sent."));
    }


    // Verify email endpoint
    @GetMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(Map.of("message", "Email verified successfully. You can now login."));
    }


    // Resend verification endpoint
    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerification(@RequestBody @Valid ResendVerificationDTO resendVerificationDTO) {
        authService.resendVerification(resendVerificationDTO.email());
        return ResponseEntity.ok(Map.of("message", "Verification email resent successfully."));
    }


    // Google Signup endpoint
    @PostMapping("/google/signup")
    public ResponseEntity<Map<String, String>> googleSignup(@RequestBody @Valid GoogleSignupRequest googleSignupRequest) {
        GoogleSignupResponse response = authService.googleSignup(googleSignupRequest.email(), googleSignupRequest.googleId());

        if (response.success()) {
            // Successful signup with automatic login
            return ResponseEntity.ok(Map.of(
                    "message", response.message(),
                    "jwtToken", response.jwtToken(),
                    "refreshToken", response.refreshToken(),
                    "userId", response.userId()
            ));
        } else {
            // Failed signup
            return ResponseEntity.badRequest().body(Map.of(
                    "message", response.message(),
                    "requiresLogin", String.valueOf(response.requiresLogin())
            ));
        }
    }




    //    ----------- LOGIN  ---------
//    manual login
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody @Valid LoginDto loginDTO) {
        LoginResponse response = authService.manualLogin(loginDTO.emailOrUsername(), loginDTO.password());

        return ResponseEntity.ok(Map.of(
                "jwtToken", response.jwtToken(),
                "refreshToken", response.refreshToken(),
                "message", response.message()
        ));
    }


//    login with google
    @PostMapping("/google/login")
    public ResponseEntity<Map<String, String>> googleLogin(@RequestBody @Valid GoogleLoginRequest googleLoginRequest){
        GoogleLoginResponse response = authService.googleLogin(googleLoginRequest.email(), googleLoginRequest.googleId());

        if (response.success()){
            return  ResponseEntity.ok(Map.of(
                    "message", response.message(),
                    "jwtToken", response.jwtToken(),
                    "refreshToken", response.refreshToken(),
                    "userId", response.userId()
            ));

        } else {
            // Failed login
            return ResponseEntity.badRequest().body(Map.of(
                    "message", response.message()
            ));
        }
    }


//    --------- refresh Token -----------
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshTokens(@RequestBody @Valid RefreshTokenDto refreshRequest) {
        LoginResponse response = authService.refreshTokens(refreshRequest.refreshToken());

        return ResponseEntity.ok(Map.of(
                "jwtToken", response.jwtToken(),
                "refreshToken", response.refreshToken(),
                "message", response.message()
        ));
    }



// ----------- LOGOUT -----------
// Logout - single device (current session only)
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logoutUser(
            HttpServletRequest request,
            @RequestBody @Valid LogoutRequest logoutRequest) {

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwtToken = authHeader.substring(7);
            authService.logoutSingleDevice(jwtToken, logoutRequest.refreshToken());
            return ResponseEntity.ok(Map.of("message", "Logged out successfully from this device"));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid authorization header"));
    }


    // Logout - all devices
    @PostMapping("/logout-all")
    public ResponseEntity<Map<String, String>> logoutAllDevices(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwtToken = authHeader.substring(7);
            authService.logoutAllDevices(jwtToken);
            return ResponseEntity.ok(Map.of("message", "Logged out from all devices successfully"));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid authorization header"));
    }

//    ------- LINK ACCOUNT ---

    @GetMapping("/auth-methods")
    public ResponseEntity<?> getUserAuthenticationMethods(Authentication authentication) {
        try {
            UUID userId = extractUserIdFromAuthentication(authentication);
            AuthMethodsResponse response = authService.getUserAuthenticationMethods(userId);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Failed to get authentication methods for user", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to get authentication methods"));
        }
    }

    @PostMapping("/connect-google")
    public ResponseEntity<?> connectGoogleAccount(@RequestBody LinkGoogleAccountRequest request,
                                                  Authentication authentication) {
        try {
            UUID userId = extractUserIdFromAuthentication(authentication);
            LinkProviderResponse response = authService.connectGoogleAccount(userId, request);
            return ResponseEntity.ok(response);
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to connect Google account for user", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to connect Google account");
        }
    }

    @PostMapping("/enable-password")
    public ResponseEntity<?> enablePasswordAuthentication(@RequestBody AddPasswordRequest request,
                                                          Authentication authentication) {
        try {
            UUID userId = extractUserIdFromAuthentication(authentication);
            LinkProviderResponse response = authService.enablePasswordAuthentication(userId, request);
            return ResponseEntity.ok(response);
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to enable password authentication for user", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to enable password authentication");
        }
    }


// ------------ RESET PASSWORD -----------
//    initaite password reste process
    // Update your password reset endpoints to use DTOs

    @PostMapping("/password-reset/initiate")
    public ResponseEntity<PasswordResetResponse> initiatePasswordReset(
            @Valid @RequestBody InitiatePasswordResetRequest request) {
        try {
            authService.initiatePasswordReset(request);
            return ResponseEntity.ok(PasswordResetResponse.success("Password reset OTP sent to your email"));
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to initiate password reset", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(PasswordResetResponse.error("Failed to initiate password reset"));
        }
    }

    @PostMapping("/password-reset/verify")
    public ResponseEntity<PasswordResetResponse> verifyOtpAndResetPassword(
            @Valid @RequestBody VerifyOtpAndResetPasswordRequest request) {
        try {
            authService.verifyOtpAndResetPassword(request);
            return ResponseEntity.ok(PasswordResetResponse.success("Password reset successfully"));
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to reset password", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(PasswordResetResponse.error("Failed to reset password"));
        }
    }

    @PostMapping("/password-reset/resend")
    public ResponseEntity<PasswordResetResponse> resendPasswordResetOtp(
            @Valid @RequestBody ResendOtpRequest request) {
        try {
            authService.resendPasswordResetOtp(request);
            return ResponseEntity.ok(PasswordResetResponse.success("New OTP sent to your email"));
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to resend OTP", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(PasswordResetResponse.error("Failed to resend OTP"));
        }
    }

//for frontend to check validation status
    @GetMapping("/password-reset/validate-otp/{otp}")
    public ResponseEntity<ValidateOtpResponse> validatePasswordResetOtp(@PathVariable String otp) {
        try {
            ValidateOtpResponse response = authService.validatePasswordResetOtp(otp);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Failed to validate OTP", e);
            return ResponseEntity.ok(new ValidateOtpResponse(false));
        }
    }

//    check if user can change password
    @GetMapping("/password-reset/check-eligibility")
    public ResponseEntity<PasswordResetEligibilityResponse> checkPasswordResetEligibility(
            @RequestBody PasswordResetEligibiltyRequest  passwordResetEligibiltyRequest) {
        try {
            PasswordResetEligibilityResponse response = authService.checkPasswordResetEligibility(passwordResetEligibiltyRequest.email());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Failed to check password reset eligibility", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new PasswordResetEligibilityResponse(false,
                            "Failed to check eligibility", false, false));
        }
    }



    // Helper method - adjust based on your JWT structure
    private UUID extractUserIdFromAuthentication(Authentication authentication) {
        try {
            // Option 1: If JWT subject is user ID (recommended)
            String userIdString = authentication.getName();
            return UUID.fromString(userIdString);

        } catch (Exception e) {
            logger.error("Failed to extract user ID from authentication", e);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid authentication");
        }
    }


}
