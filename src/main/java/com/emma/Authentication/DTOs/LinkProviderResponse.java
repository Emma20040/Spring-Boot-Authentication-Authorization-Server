package com.emma.Authentication.DTOs;

import java.time.LocalDateTime;

public record LinkProviderResponse(
        boolean success,
        String message,
        String linkedProvider,
        LocalDateTime linkedAt
) {
    public static LinkProviderResponse success(String message, String provider, LocalDateTime linkedAt) {
        return new LinkProviderResponse(true, message, provider, linkedAt);
    }
}