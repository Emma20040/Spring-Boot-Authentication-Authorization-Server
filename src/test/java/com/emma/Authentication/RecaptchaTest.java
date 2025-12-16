package com.emma.Authentication;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:h2:mem:testdb",
                "spring.datasource.driver-class-name=org.h2.Driver",
                "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.data.redis.enabled=false",
                "spring.security.enabled=false"
        })
//@TestPropertySource(locations = "classpath:application-test.properties", ignoreResourceNotFound = true)
public class RecaptchaTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testGetSiteKey() {
        String url = "http://localhost:" + port + "/recaptchaV3/site-key";
        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);

        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().isEmpty());
    }

    @Test
    public void testVerifyWithoutToken() {
        String url = "http://localhost:" + port + "/recaptchaV3/verify";

        // Send POST with empty form data to trigger missing parameter error
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", ""); // Empty token triggers 400

        ResponseEntity<String> response = restTemplate.postForEntity(url, formData, String.class);

        assertEquals(400, response.getStatusCodeValue());
    }
}