package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.NotBlank;

public record ResendVerificationDTO(
        @NotBlank String email
) {
}
