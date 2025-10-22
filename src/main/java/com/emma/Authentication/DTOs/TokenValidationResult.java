package com.emma.Authentication.DTOs;

public record TokenValidationResult(
        boolean isValid,
        String email,
        String googleId,
        String errorMessage
) {
    public static TokenValidationResult valid(String email, String googleId) {
        return new TokenValidationResult(true, email, googleId, null);
    }

    public static TokenValidationResult invalid(String errorMessage) {
        return new TokenValidationResult(false, null, null, errorMessage);
    }

    public GoogleSignupResponse getErrorResponse() {
        return GoogleSignupResponse.builder()
                .message(errorMessage)
                .success(false)
                .requiresLogin(false)
                .build();
    }
}