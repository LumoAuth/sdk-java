package io.lumoauth.spring;

import io.lumoauth.LumoAgent;
import io.lumoauth.LumoAuth;
import io.lumoauth.TokenProvider;
import io.lumoauth.aauth.AAuthClient;
import io.lumoauth.aauth.AAuthKeys;
import io.lumoauth.errors.LumoAuthConfigException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LumoAuthAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(LumoAuthAutoConfiguration.class));

    @Test
    void createsAClientFromProperties() {
        runner.withPropertyValues("lumoauth.url=https://lumo.test/", "lumoauth.org-id=acme", "lumoauth.api-key=k", "lumoauth.timeout=5s")
            .run(context -> {
                assertThat(context).hasSingleBean(LumoAuth.class).doesNotHaveBean(LumoAgent.class).doesNotHaveBean(AAuthClient.class);
                LumoAuth lumo = context.getBean(LumoAuth.class);
                assertThat(lumo.baseUrl()).isEqualTo("https://lumo.test");
                assertThat(lumo.orgId()).contains("acme");
                assertThat(lumo.apiClientConfig().defaultHeaders()).containsKey("X-API-Key");
                assertThat(lumo.transport().timeout().toSeconds()).isEqualTo(5);
                assertThat(context.getBean(LumoAuthProperties.class).issuer()).isEqualTo("https://lumo.test/orgs/acme/api/v1");
            });
    }

    @Test
    void clientWithoutCredentialStillExists() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(LumoAuth.class);
            LumoAuth lumo = context.getBean(LumoAuth.class);
            assertThat(lumo.baseUrl()).isEqualTo(LumoAuth.DEFAULT_BASE_URL);
            assertThatThrownBy(lumo::apiClientConfig).isInstanceOf(LumoAuthConfigException.class);
        });
    }

    @Test
    void tokenProviderBeanBecomesTheCredential() {
        runner.withUserConfiguration(ProviderConfig.class).run(context ->
            assertThat(context.getBean(LumoAuth.class).apiClientConfig().defaultHeaders()).containsEntry("Authorization", "Bearer from-bean"));
    }

    @Test
    void createsAgentAndAAuthClientsWhenConfigured() {
        String pem = AAuthKeys.generateKeypair().privateKeyPem();
        runner.withPropertyValues("lumoauth.url=https://lumo.test", "lumoauth.org-id=acme",
                "lumoauth.agent.client-id=cid", "lumoauth.agent.client-secret=sec", "lumoauth.agent.scopes=a,b",
                "lumoauth.aauth.agent-identifier=https://agent.test", "lumoauth.aauth.private-key-pem=" + pem.replace("\n", "\\n"), "lumoauth.aauth.kid=k9")
            .run(context -> {
                assertThat(context).hasSingleBean(LumoAgent.class).hasSingleBean(AAuthClient.class);
                assertThat(context.getBean(LumoAgent.class).clientId()).isEqualTo("cid");
                assertThat(context.getBean(AAuthClient.class).publicJwk().kid()).isEqualTo("k9");
                assertThat(context.getBean(AAuthClient.class).issuer()).isEqualTo("https://lumo.test/orgs/acme/api/v1");
            });
    }

    @Test
    void userDefinedBeansWin() {
        runner.withUserConfiguration(CustomClient.class).withPropertyValues("lumoauth.api-key=k").run(context -> {
            assertThat(context).hasSingleBean(LumoAuth.class);
            assertThat(context.getBean(LumoAuth.class).baseUrl()).isEqualTo("https://custom.test");
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class ProviderConfig {
        @Bean
        TokenProvider tokenProvider() {
            return () -> "from-bean";
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomClient {
        @Bean
        LumoAuth lumoAuth() {
            return LumoAuth.builder().baseUrl("https://custom.test").apiKey("x").build();
        }
    }
}
