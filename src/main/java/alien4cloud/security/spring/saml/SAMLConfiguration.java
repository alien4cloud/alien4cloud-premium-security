package alien4cloud.security.spring.saml;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import alien4cloud.security.AuthorizationUtil;
import alien4cloud.security.spring.A4CPremiumAuthenticationProvider;
import alien4cloud.security.spring.Alien4CloudAccessDeniedHandler;
import alien4cloud.security.spring.Alien4CloudAuthenticationProvider;

@Configuration
@ConditionalOnProperty(value = "saml.enabled", havingValue = "true")
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
public class SAMLConfiguration extends WebSecurityConfigurerAdapter {
    @Inject
    private Alien4CloudAccessDeniedHandler accessDeniedHandler;

    private Alien4CloudAuthenticationProvider alienAuthenticationProvider = new A4CPremiumAuthenticationProvider();
    @Inject
    private SAMLEntryPoint samlEntryPoint;
    @Inject
    private SAMLLogoutFilter samlLogoutFilter;
    @Inject
    private MetadataDisplayFilter metadataDisplayFilter;
    @Inject
    private MetadataGeneratorFilter metadataGeneratorFilter;
    @Inject
    private SAMLLogoutProcessingFilter samlLogoutProcessingFilter;
    @Inject
    private SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter;
    @Inject
    private SAMLProcessingFilter samlWebSSOProcessingFilter;
    @Inject
    private SimpleUrlLogoutSuccessHandler successLogoutHandler;

    /**
     * Returns the authentication manager currently used by Spring.
     * It represents a bean definition with the aim allow wiring from
     * other classes performing the Inversion of Control (IoC).
     *
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Defines the web based security configuration.
     *
     * @param http It allows configuring web based security for specific http requests.
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());

        // Define the security filter chain in order to support SSO Auth by using SAML 2.0
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"), metadataDisplayFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"), samlWebSSOProcessingFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"), samlWebSSOHoKProcessingFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"), samlLogoutProcessingFilter));
        FilterChainProxy samlFilters = new FilterChainProxy(chains);

        // configure the HttpSecurity
        AuthorizationUtil.configure(http, successLogoutHandler);
        http.httpBasic().authenticationEntryPoint(samlEntryPoint);
        http.addFilterBefore(metadataGeneratorFilter, ChannelProcessingFilter.class).addFilterAfter(samlFilters, BasicAuthenticationFilter.class);
    }

    @Bean
    @Primary
    public Alien4CloudAuthenticationProvider authenticationProvider() {
        return alienAuthenticationProvider;
    }

    /**
     * Sets a custom authentication provider.
     *
     * @param auth SecurityBuilder used to create an AuthenticationManager.
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
}
