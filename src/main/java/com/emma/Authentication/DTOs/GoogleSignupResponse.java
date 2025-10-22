package com.emma.Authentication.DTOs;

public record GoogleSignupResponse(String message, boolean success, boolean requiresLogin, String userId, String jwtToken, String refreshToken) {
    public static GoogleSignupResponseBuilder builder() {
        return new GoogleSignupResponseBuilder();
    }

    public static class GoogleSignupResponseBuilder {
        private String message;
        private boolean success;
        private boolean requiresLogin;
        private String userId;
        private String jwtToken;
        private String refreshToken;

        public GoogleSignupResponseBuilder message(String message) {
            this.message = message;
            return this;
        }

        public GoogleSignupResponseBuilder success(boolean success) {
            this.success = success;
            return this;
        }

        public GoogleSignupResponseBuilder requiresLogin(boolean requiresLogin) {
            this.requiresLogin = requiresLogin;
            return this;
        }

        public GoogleSignupResponseBuilder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public GoogleSignupResponseBuilder jwtToken(String jwtToken) {
            this.jwtToken = jwtToken;
            return this;
        }

        public GoogleSignupResponseBuilder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public GoogleSignupResponse build() {
            return new GoogleSignupResponse(message, success, requiresLogin, userId, jwtToken, refreshToken);
        }
    }
}
