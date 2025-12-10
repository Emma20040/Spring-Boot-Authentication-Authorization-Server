package com.emma.Authentication.RecaptchaV3;



import com.emma.Authentication.RecaptchaV3.GoogleResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
public class RecaptchaTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RestTemplate restTemplate;

    @Test
    public void testGetSiteKey() throws Exception {
        mockMvc.perform(get("/recaptchaV3/site-key"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.isEmptyString())));
    }

    @Test
    public void testVerifyWithoutToken() throws Exception {
        mockMvc.perform(post("/recaptchaV3/verify"))
                .andExpect(status().isBadRequest());  // Missing required parameter
    }

    @Test
    public void testVerifyWithValidToken() throws Exception {
        // Mock Google's successful response
        GoogleResponse googleResponse = new GoogleResponse();
        googleResponse.setSuccess(true);
        googleResponse.setScore(0.9f);
        googleResponse.setAction("test");

        when(restTemplate.getForObject(anyString(), eq(GoogleResponse.class)))
                .thenReturn(googleResponse);

        mockMvc.perform(post("/recaptchaV3/verify")
                        .param("token", "any-valid-token"))
                .andExpect(status().isOk())
                .andExpect(content().string("reCAPTCHA validation passed!"));
    }

    @Test
    public void testVerifyWithFailedGoogleResponse() throws Exception {
        // Mock Google's failed response
        GoogleResponse googleResponse = new GoogleResponse();
        googleResponse.setSuccess(false);  // Google says token is invalid

        when(restTemplate.getForObject(anyString(), eq(GoogleResponse.class)))
                .thenReturn(googleResponse);

        mockMvc.perform(post("/recaptchaV3/verify")
                        .param("token", "invalid-token"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("reCAPTCHA failed")));
    }
}