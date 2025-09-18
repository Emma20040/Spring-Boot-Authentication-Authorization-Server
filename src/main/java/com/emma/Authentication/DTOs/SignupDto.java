package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.*;

public record SignupDto(
        @NotBlank(message = "Username is required")
        String username,

        @NotBlank(message="email required for signup")
        @Email String email,

        @NotBlank(message="password required for manual signup")
//        disable password validation for testing
//        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$",
//                                           message = "Password must contain at least one uppercase, one lowercase, and one number")

                String password
                        ) {
}
