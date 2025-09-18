package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.NotBlank;

public record LoginDto(
        @NotBlank(message = "password required")
        String emailOrUsername,

        @NotBlank(message = "password required")
        String password
) {
}
