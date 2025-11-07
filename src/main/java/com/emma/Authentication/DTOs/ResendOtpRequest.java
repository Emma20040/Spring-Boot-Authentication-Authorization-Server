package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;


public record ResendOtpRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Valid email is required")
        String email
) {}