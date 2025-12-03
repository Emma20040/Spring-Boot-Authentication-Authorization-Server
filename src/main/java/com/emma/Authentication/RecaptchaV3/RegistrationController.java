package com.emma.Authentication.RecaptchaV3;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@RequestMapping("/recaptchaV3")
public class RegistrationController {

    @Autowired
    private ICaptchaService captchaService;



    @PostMapping
    @ResponseBody
    public GenericResponse registerUserAccount(@Valid UserDto accountDto, HttpServletRequest request) {
        String response = request.getParameter("response");
        captchaService.processResponse(response, CaptchaService.REGISTER_ACTION);

        // rest of implementation
    }


}
