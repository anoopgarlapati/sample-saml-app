package com.github.anoopgarlapati.samples.saml.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Value("${saml.idp.id}")
    private String samlIdpId;
    @Value("${saml.idp.metadata-uri}")
    private String samlIdpMetadataUri;
    @Value("${saml.signature-algorithm}")
    private String samlSignatureAlgorithm;

    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated()
            ).saml2Login(withDefaults());
        return http.build();
    }

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        KeyPair signingKey = generateSigningKey();
        X509Certificate signingCert = generateSigningCert(signingKey);
        Saml2X509Credential saml2X509Credential = Saml2X509Credential.signing(signingKey.getPrivate(), signingCert);
        RelyingPartyRegistration registration = RelyingPartyRegistrations.fromMetadataLocation(samlIdpMetadataUri)
            .registrationId(samlIdpId)
            .signingX509Credentials(saml2X509Credentials -> saml2X509Credentials.add(saml2X509Credential))
            .assertingPartyDetails(assertingPartyDetails -> assertingPartyDetails
                .wantAuthnRequestsSigned(true)
                .signingAlgorithms(algorithms -> {
                    algorithms.clear();
                    algorithms.add(samlSignatureAlgorithm);
                })
            ).build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    @Bean
    RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(RelyingPartyRegistrationRepository registrations) {
        return new DefaultRelyingPartyRegistrationResolver(registrations);
    }

    @Bean
    Saml2AuthenticationTokenConverter authentication(RelyingPartyRegistrationResolver registrations) {
        return new Saml2AuthenticationTokenConverter(registrations);
    }

    @Bean
    FilterRegistrationBean<Saml2MetadataFilter> metadata(RelyingPartyRegistrationResolver registrations) {
        Saml2MetadataFilter metadata = new Saml2MetadataFilter(registrations, new OpenSamlMetadataResolver());
        FilterRegistrationBean<Saml2MetadataFilter> filter = new FilterRegistrationBean<>(metadata);
        filter.setOrder(-101);
        return filter;
    }

    private static KeyPair generateSigningKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static X509Certificate generateSigningCert(KeyPair keyPair) {
        try {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            final X509CertificateHolder certHolder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Sample SAML Application, O=VMware, L=Bengaluru, C=IN"),
                BigInteger.ONE,
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Name("CN=Sample SAML Application, O=VMware, L=Bengaluru, C=IN"),
                keyPair.getPublic()
            ).build(signer);
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

}
