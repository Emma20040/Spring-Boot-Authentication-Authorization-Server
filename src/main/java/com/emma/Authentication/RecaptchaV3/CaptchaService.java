package com.emma.Authentication.RecaptchaV3;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class CaptchaService implements ICaptchaService {

    public static final String REGISTER_ACTION = "register";
    @Value("${GOOGLE_RECAPTCHA_VERIFY_URL}")
    private static final String GOOGLE_RECAPTCHA_VERIFY_URL =
            "https://www.google.com/recaptcha/api/siteverify";

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private CaptchaSettings captchaSettings;

    @Autowired
    private IReCaptchaAttemptService reCaptchaAttemptService;

    @Autowired
    private HttpServletRequest httpServletRequest;


    @Override
    public String getReCaptchaSite() {
        return captchaSettings.getSite();
    }

    private String getClientIp() {
        String xfHeader = httpServletRequest.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0].trim();
        }
        return httpServletRequest.getRemoteAddr();
    }

    @Override
    public void processResponse(String response, String action) {
        String verifyUri = String.format("%s?secret=%s&response=%s",
                GOOGLE_RECAPTCHA_VERIFY_URL, captchaSettings.getSecret(), response);

        GoogleResponse googleResponse = restTemplate.getForObject(verifyUri, GoogleResponse.class);
        if(!googleResponse.isSuccess() || !googleResponse.getAction().equals(action)
                || googleResponse.getScore() < captchaSettings.getThreshold()) {

            throw new ReCaptchaInvalidException("reCaptcha was not successfully validated");
        }
        reCaptchaAttemptService.reCaptchaSucceeded(getClientIp());
    }
}
