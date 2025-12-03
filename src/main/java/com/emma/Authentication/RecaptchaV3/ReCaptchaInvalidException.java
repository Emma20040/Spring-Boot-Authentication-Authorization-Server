package com.emma.Authentication.RecaptchaV3;

public class ReCaptchaInvalidException extends RuntimeException {
    public ReCaptchaInvalidException(String message) {
        super(message);
    }
}
