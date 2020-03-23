package alien4cloud.security.spring.saml;

import javax.inject.Inject;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

/**
 * Configuration of base SAML beans.
 */
@Slf4j
@Configuration
@ConditionalOnProperty(value = "saml.enabled", havingValue = "true")
public class SAMLBaseConfiguration {
    @Inject
    private SAMLUserDetailServiceImpl samlUserDetailsServiceImpl;

    @Value("${saml.logoutUrl:#{null}}")
    private String logoutRedirectUrl;

    @Value("${saml.ctxProvider.contextPath:#{null}}")
    private static String samlCtxProviderContextPath;

    @Value("${saml.ctxProvider.serverName:#{null}}")
    private static String samlCtxProviderServerName;

    @Value("${saml.ctxProvider.scheme:#{null}}")
    private static String samlCtxProviderScheme;

    @Value("${saml.ctxProvider.serverPort:#{null}}")
    private static Integer samlCtxProviderServerPort;

    // SAML Authentication Provider responsible for validating of received SAML messages
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }

    // Overrides default logout processing filter with the one processing SAML
    // messages
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] { logoutHandler() }, new LogoutHandler[] { logoutHandler() });
    }

    // Handler for successful logout
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        String targetLogoutUrl = logoutRedirectUrl == null ? "/" : logoutRedirectUrl;
        successLogoutHandler.setDefaultTargetUrl(targetLogoutUrl);
        return successLogoutHandler;
    }

    // Logout handler terminating local session
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    // Provider of default SAML Context
    @Bean
    public static SAMLContextProvider contextProvider() {
        if (samlCtxProviderServerName != null && samlCtxProviderScheme != null) {
            log.info("SAML Context provider scheme, server name provided : {}://{}, will use SAMLContextProviderLB as SAMLContextProvider", samlCtxProviderScheme, samlCtxProviderServerName);
            SAMLContextProviderLB samlContextProvider = new SAMLContextProviderLB();
            samlContextProvider.setScheme(samlCtxProviderScheme);
            samlContextProvider.setServerName(samlCtxProviderServerName);
            samlContextProvider.setContextPath(samlCtxProviderContextPath);
            if (samlCtxProviderServerPort != null) {
                samlContextProvider.setServerPort(samlCtxProviderServerPort);
            }
            return samlContextProvider;
        } else {
            log.info("No SAML Context provider scheme, server name provided, will use SAMLContextProviderImpl as SAMLContextProvider");
            return new SAMLContextProviderImpl();
        }
    }

    // Initialization of OpenSAML library
    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }

    // Logger for SAML messages and events
    @Bean
    public static SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    // SAML 2.0 WebSSO Assertion Consumer
    @Bean
    public static WebSSOProfileConsumer webSSOprofileConsumer(
            @Value("${saml.maxAuthenticationAge:null}") Long maxAuthenticationAge,
            @Value("${saml.maxAssertionTime:null}") Integer maxAssertionTime,
            @Value("${saml.responseSkew:60}") Integer responseSkew,
            @Value("${saml.includeAllAttributes:false}") Boolean includeAllAttributes
            ) {
        WebSSOProfileConsumerImpl consumer = new WebSSOProfileConsumerImpl();
        if (maxAuthenticationAge != null) {
            consumer.setMaxAuthenticationAge(maxAuthenticationAge);
        }
        if (maxAssertionTime != null) {
            consumer.setMaxAssertionTime(maxAssertionTime);
        }
        if (responseSkew != null) {
            consumer.setResponseSkew(responseSkew);
        }
        if (includeAllAttributes != null) {
            consumer.setIncludeAllAttributes(includeAllAttributes);
        }
        return consumer;
    }

    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // SAML 2.0 Web SSO profile
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    // SAML 2.0 Holder-of-Key Web SSO profile
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // SAML 2.0 ECP profile
    @Bean
    public WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl();
    }

    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful global logout
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter(SimpleUrlLogoutSuccessHandler successLogoutHandler,
            SecurityContextLogoutHandler logoutHandler) {
        return new SAMLLogoutProcessingFilter(successLogoutHandler, logoutHandler);
    }

    // Overrides default logout processing filter with the one processing SAML messages
    @Bean
    public SAMLLogoutFilter samlLogoutFilter(SimpleUrlLogoutSuccessHandler successLogoutHandler, SecurityContextLogoutHandler logoutHandler) {
        return new SAMLLogoutFilter(successLogoutHandler, new LogoutHandler[] { logoutHandler }, new LogoutHandler[] { logoutHandler });
    }

    // Handler deciding where to redirect user after successful login
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/");
        return successRedirectHandler;
    }

    // Handler deciding where to redirect user after failed login
    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/");
        return failureHandler;
    }

    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    // Entry point to initialize authentication, default values taken from
    // properties file
    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    @Bean
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter(SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler,
            SimpleUrlAuthenticationFailureHandler authenticationFailureHandler) throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
        // authentication manager will be set later in the SAMLConfiguration bean. We need lazy setting here but spring checks if not null in afterPropertiesSet
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authentication -> null);
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler);
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
        return samlWebSSOHoKProcessingFilter;
    }

    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter(SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler,
            SimpleUrlAuthenticationFailureHandler authenticationFailureHandler) throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        // authentication manager will be set later in the SAMLConfiguration bean. We need lazy setting here but spring checks if not null in afterPropertiesSet
        samlWebSSOProcessingFilter.setAuthenticationManager(authentication -> null);
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler);
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
        return samlWebSSOProcessingFilter;
    }
}
