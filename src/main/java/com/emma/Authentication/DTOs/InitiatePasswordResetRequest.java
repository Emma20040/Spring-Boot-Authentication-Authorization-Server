package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record InitiatePasswordResetRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Valid email is required")
        String email
) {}







