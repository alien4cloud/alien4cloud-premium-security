package alien4cloud.security.spring.saml;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;

import javax.inject.Inject;

import org.apache.commons.httpclient.HttpClient;
import org.opensaml.saml2.metadata.provider.*;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

/**
 * Configuration of SAML meta data.
 */
@ConditionalOnProperty(value = "saml.enabled", havingValue = "true")
@Configuration
public class MetadataConfiguration {
    @Value("${saml.metadata.idp.url:null}")
    private String idpMetadataURL;
    @Value("${saml.metadata.idp.file:null}")
    private String idpMetadataFile;
    @Inject
    private StaticBasicParserPool parserPool;
    @Inject
    private HttpClient httpClient;

    // Setup advanced info about metadata
    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
    }

    @Bean
    @Qualifier("default-idp")
    public ExtendedMetadataDelegate ssoCircleExtendedMetadataProvider() throws MetadataProviderException {
        Timer backgroundTaskTimer = new Timer(true);
        AbstractMetadataProvider metadataProvider;
        if (idpMetadataURL == null) {
            if (idpMetadataFile == null) {
                metadataProvider = new HTTPMetadataProvider(backgroundTaskTimer, httpClient, idpMetadataURL);
            } else {
                metadataProvider = new FileBackedHTTPMetadataProvider(backgroundTaskTimer, httpClient, idpMetadataURL, idpMetadataFile);
            }
        } else {
            // load from file
            metadataProvider = new FilesystemMetadataProvider(backgroundTaskTimer, Paths.get(idpMetadataFile).toFile());
        }
        metadataProvider.setParserPool(parserPool);
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(metadataProvider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(true);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        return extendedMetadataDelegate;
    }

    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(ssoCircleExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }
}
