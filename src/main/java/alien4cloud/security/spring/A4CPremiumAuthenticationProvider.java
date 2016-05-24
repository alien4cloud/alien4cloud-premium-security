package alien4cloud.security.spring;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationToken;

/**
 * Specific Alien4Cloud Authentication Provider that provides SAML support
 */
public class A4CPremiumAuthenticationProvider extends Alien4CloudAuthenticationProvider {
    @Override
    public boolean supports(Class<?> authenticationClass) {
        if (wrappedProvider instanceof SAMLAuthenticationProvider) {
            return SAMLAuthenticationToken.class.isAssignableFrom(authenticationClass)
                    || UsernamePasswordAuthenticationToken.class.isAssignableFrom(authenticationClass);
        }
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authenticationClass);
    }
}