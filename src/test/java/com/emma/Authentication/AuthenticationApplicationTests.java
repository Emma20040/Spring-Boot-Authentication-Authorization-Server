package com.emma.Authentication;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(
        properties = {
                "spring.datasource.url=jdbc:h2:mem:testdb",
                "spring.datasource.driver-class-name=org.h2.Driver",
                "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.data.redis.enabled=false",
                "spring.security.enabled=false"
        }
)
class AuthenticationApplicationTests {

	@Test
	void contextLoads() {
	}

}
