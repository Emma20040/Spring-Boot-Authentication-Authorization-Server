package com.emma.Authentication.RecaptchaV3;

public interface ICaptchaService {
    void processResponse(String response, String action);
    String getReCaptchaSite();
}