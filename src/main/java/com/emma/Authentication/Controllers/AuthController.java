package com.emma.Authentication.Controllers;

import com.emma.Authentication.DTOs.ResendVerificationDTO;
import com.emma.Authentication.DTOs.SignupDto;
import com.emma.Authentication.Services.AuthService;
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
}
