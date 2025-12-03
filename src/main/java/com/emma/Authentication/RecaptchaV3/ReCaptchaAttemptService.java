package com.emma.Authentication.RecaptchaV3;

import org.springframework.stereotype.Service;

@Service
public class ReCaptchaAttemptService implements IReCaptchaAttemptService {

    @Override
    public void reCaptchaSucceeded(String clientIP) {
        // Implementation what will be done if successful reCAPTCHA attempts, but for this project i will
        // leave the implement for anyone to do it base on thier system requirements or security plan
    }

    @Override
    public void reCaptchaFailed(String clientIP) {
        // Implementation to handle failed reCAPTCHA attempts, same case as above

    }
}
