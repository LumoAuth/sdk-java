package io.lumoauth.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

class LumoAuthLoginAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(LumoAuthAutoConfiguration.class, LumoAuthSecurityAutoConfiguration.class,
            LumoAuthLoginAutoConfiguration.class, SecurityAutoConfiguration.class, OAuth2ClientAutoConfiguration.class))
        .withPropertyValues("lumoauth.url=https://lumo.test", "lumoauth.org-id=acme");

    @Test
    void registersLumoAuthAsAnOidcClient() {
        runner.withPropertyValues("lumoauth.login.client-id=cid", "lumoauth.login.client-secret=sec").run(context -> {
            assertThat(context).hasSingleBean(ClientRegistrationRepository.class).hasSingleBean(SecurityFilterChain.class).hasBean("lumoAuthSecurityFilterChain");
            ClientRegistration registration = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("lumoauth");
            assertThat(registration.getClientId()).isEqualTo("cid");
            assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            assertThat(registration.getScopes()).containsExactly("openid", "profile", "email");
            assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo("https://lumo.test/orgs/acme/api/v1/oauth/authorize");
            assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo("https://lumo.test/orgs/acme/api/v1/oauth/token");
            assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri()).isEqualTo("https://lumo.test/orgs/acme/api/v1/oauth/userinfo");
            assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo("https://lumo.test/orgs/acme/api/v1/.well-known/jwks.json");
            assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo("https://lumo.test/orgs/acme/api/v1");
            assertThat(registration.getRedirectUri()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
        });
    }

    @Test
    void publicClientsUsePkceOnly() {
        runner.withPropertyValues("lumoauth.login.client-id=cid", "lumoauth.login.registration-id=lumo").run(context -> {
            ClientRegistration registration = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("lumo");
            assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
            assertThat(registration.getClientSecret()).isNullOrEmpty();
        });
    }

    @Test
    void nothingWithoutAClientId() {
        runner.run(context -> assertThat(context).doesNotHaveBean(ClientRegistrationRepository.class).doesNotHaveBean("lumoAuthSecurityFilterChain"));
    }

    @Test
    void backsOffForUserDefinedChainsAndWhenDisabled() {
        runner.withPropertyValues("lumoauth.login.client-id=cid").withUserConfiguration(OwnChain.class).run(context -> {
            assertThat(context).hasSingleBean(SecurityFilterChain.class).doesNotHaveBean("lumoAuthSecurityFilterChain").hasSingleBean(ClientRegistrationRepository.class);
        });
        runner.withPropertyValues("lumoauth.login.client-id=cid", "lumoauth.login.default-filter-chain=false").run(context ->
            assertThat(context).doesNotHaveBean("lumoAuthSecurityFilterChain").hasSingleBean(ClientRegistrationRepository.class));
    }

    @Configuration(proxyBeanMethods = false)
    static class OwnChain {
        @Bean
        SecurityFilterChain own(HttpSecurity http) throws Exception {
            return http.build();
        }
    }
}
