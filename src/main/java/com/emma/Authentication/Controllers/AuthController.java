package com.emma.Authentication.Controllers;

import com.emma.Authentication.DTOs.*;
import com.emma.Authentication.Services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

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


    //    ----------- LOGIN  ---------
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody @Valid LoginDto loginDTO) {
        LoginResponse response = authService.manualLogin(loginDTO.emailOrUsername(), loginDTO.password());

        return ResponseEntity.ok(Map.of(
                "jwtToken", response.jwtToken(),
                "refreshToken", response.refreshToken(),
                "message", response.message()
        ));
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


}
