package com.emma.Authentication.DTOs;


public record PasswordResetResponse(
        boolean success,
        String message
) {
    public static PasswordResetResponse success(String message) {
        return new PasswordResetResponse(true, message);
    }

    public static PasswordResetResponse error(String message) {
        return new PasswordResetResponse(false, message);
    }
}