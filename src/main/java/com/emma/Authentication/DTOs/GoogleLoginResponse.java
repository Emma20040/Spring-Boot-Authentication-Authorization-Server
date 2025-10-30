package com.emma.Authentication.DTOs;

public record GoogleLoginResponse(
        String message,
        boolean success,
        String userId,
        String jwtToken,
        String refreshToken
) {
    public static GoogleLoginResponseBuilder builder() {
        return new GoogleLoginResponseBuilder();
    }

    public static class GoogleLoginResponseBuilder {
        private String message;
        private boolean success;
        private String userId;
        private String jwtToken;
        private String refreshToken;

        public GoogleLoginResponseBuilder message(String message) {
            this.message = message;
            return this;
        }

        public GoogleLoginResponseBuilder success(boolean success) {
            this.success = success;
            return this;
        }

        public GoogleLoginResponseBuilder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public GoogleLoginResponseBuilder jwtToken(String jwtToken) {
            this.jwtToken = jwtToken;
            return this;
        }

        public GoogleLoginResponseBuilder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public GoogleLoginResponse build() {
            return new GoogleLoginResponse(message, success, userId, jwtToken, refreshToken);
        }
    }
}
