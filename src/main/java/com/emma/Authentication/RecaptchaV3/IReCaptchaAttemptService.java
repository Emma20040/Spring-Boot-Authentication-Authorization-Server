package com.emma.Authentication.RecaptchaV3;

public interface IReCaptchaAttemptService {
    void reCaptchaSucceeded(String clientIP);
    void reCaptchaFailed(String clientIP);
}
