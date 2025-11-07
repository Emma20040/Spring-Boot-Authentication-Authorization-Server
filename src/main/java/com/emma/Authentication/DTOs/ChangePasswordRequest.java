package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ChangePasswordRequest(
        @NotBlank String currentPassword,
//                @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,72}$",
//                                           message = "Password must contain at least one uppercase, one lowercase, and one number")

        @NotBlank String newPassword) {
}
