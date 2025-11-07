package com.emma.Authentication.DTOs;

// Add this record to your PasswordResetDTOs.java
public record PasswordResetEligibilityResponse(
        boolean eligible,
        String message,
        boolean hasPassword,
        boolean hasGoogleAuth
) {
}
