package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;


public record PasswordResetEligibiltyRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Valid email is required")
        String email
) {}
