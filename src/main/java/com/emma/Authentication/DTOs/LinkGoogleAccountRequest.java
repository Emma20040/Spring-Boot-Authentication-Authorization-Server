package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.NotBlank;

public record LinkGoogleAccountRequest(
        @NotBlank String providerToken,
        String password
) {
}
