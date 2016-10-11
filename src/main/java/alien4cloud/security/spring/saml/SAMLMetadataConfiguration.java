package alien4cloud.security.spring.saml;

import javax.inject.Inject;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;

/**
 * Manage metadata generation and display configuration.
 *
 * Note these beans are wired through the SAML Configuration bean
 */
@Configuration
public class SAMLMetadataConfiguration {
    @Inject
    private MetadataGenerator metadataGenerator;

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator);
    }

    // The filter is waiting for connections on URL suffixed with filterSuffix and presents SP metadata there
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }
}