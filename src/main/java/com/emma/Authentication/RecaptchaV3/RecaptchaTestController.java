package com.emma.Authentication.RecaptchaV3;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


import com.emma.Authentication.RecaptchaV3.ICaptchaService;
import com.emma.Authentication.RecaptchaV3.ReCaptchaInvalidException;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/recaptchaV3")
public class RecaptchaTestController {

    @Autowired
    private ICaptchaService captchaService;

    // Just get site key for frontend
    @GetMapping("/site-key")
    public ResponseEntity<String> getSiteKey() {
        return ResponseEntity.ok(captchaService.getReCaptchaSite());
    }

    // Verify token - SIMPLE!
    @PostMapping("/verify")
    public ResponseEntity<String> verifyRecaptcha(@RequestParam("token") String token) {
        try {
            captchaService.processResponse(token, "test");
            return ResponseEntity.ok("reCAPTCHA validation passed!");
        } catch (ReCaptchaInvalidException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(" reCAPTCHA failed: " + e.getMessage());
        }
    }
}