package com.emma.Authentication.DTOs;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record AddPasswordRequest(@NotBlank
                                 //        disable password validation for testing
//                                 @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,72}$",
//                                         message = "Password must contain at least one uppercase, one lowercase, and one number, and be between 8 and 72 characters long")

                                 String newPassword) {
}
