package alien4cloud.security.spring.saml;

import javax.annotation.Resource;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Component;

import alien4cloud.security.model.User;
import alien4cloud.security.users.IAlienUserDao;

@Slf4j
@Component
@ConditionalOnProperty(value = "saml.enabled", havingValue = "true")
public class SAMLUserDetailServiceImpl implements SAMLUserDetailsService {
    @Resource
    private IAlienUserDao userDao;

    @Value("${saml.mapping.email:#{null}}")
    private String emailAttribute;
    @Value("${saml.mapping.firstname:#{null}}")
    private String firstNameAttribute;
    @Value("${saml.mapping.lastname:#{null}}")
    private String lastNameAttribute;

    @Override
    public Object loadUserBySAML(SAMLCredential samlCredential) throws UsernameNotFoundException {
        String userId = samlCredential.getNameID().getValue();

        User user = userDao.find(userId);
        log.debug("User <{}> has been retrieved from SAML authentication.", user);
        if (user == null) {
            // create a user
            user = new User();
            user.setUsername(userId);

            updateUserIfChanged(samlCredential, user);

            user.setInternalDirectory(false);
        } else {
            updateUserIfChanged(samlCredential, user);
        }

        return user;
    }

    private void updateUserIfChanged(SAMLCredential samlCredential, User user) {
        if (emailAttribute != null) {
            String value = samlCredential.getAttributeAsString(emailAttribute);
            if (value != null && !value.equals(user.getEmail())) {
                user.setEmail(value);
            }
        }
        if (firstNameAttribute != null) {
            String value = samlCredential.getAttributeAsString(firstNameAttribute);
            if (value != null && !value.equals(user.getFirstName())) {
                user.setFirstName(value);
            }
        }
        if (lastNameAttribute != null) {
            String value = samlCredential.getAttributeAsString(lastNameAttribute);
            if (value != null && !value.equals(user.getLastName())) {
                user.setLastName(value);
            }
        }
    }
}
