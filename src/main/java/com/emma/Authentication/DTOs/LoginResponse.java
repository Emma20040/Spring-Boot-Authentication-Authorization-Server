package com.emma.Authentication.DTOs;

public record LoginResponse(String jwtToken, String refreshToken, String message) {
}
