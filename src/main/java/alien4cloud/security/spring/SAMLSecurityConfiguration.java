package alien4cloud.security.spring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Override default security configration from Alien4Cloud to use the A4CPremiumAuthenticationProvider.
 */
@Configuration
public class SAMLSecurityConfiguration {
    @Bean
    @Primary
    public Alien4CloudAuthenticationProvider authenticationProvider() {
        //
        return new A4CPremiumAuthenticationProvider();
    }
}
