package io.lumoauth.spring;

import io.lumoauth.LumoAgent;
import io.lumoauth.LumoAuth;
import io.lumoauth.TokenProvider;
import io.lumoauth.aauth.AAuthClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.net.http.HttpClient;

/**
 * Creates the SDK entry points from {@code lumoauth.*} properties:
 * <ul>
 *   <li>a {@link LumoAuth} client, always (without a credential when no API key
 *       and no {@link TokenProvider} bean is configured, so unauthenticated
 *       endpoints and bearer-token introspection still work);</li>
 *   <li>a {@link LumoAgent} when {@code lumoauth.agent.client-id} is set;</li>
 *   <li>an {@link AAuthClient} when {@code lumoauth.aauth.agent-identifier} is set.</li>
 * </ul>
 * Each backs off when the application defines its own bean of that type. A
 * {@link HttpClient} bean, if present, is used for every request.
 */
@AutoConfiguration
@EnableConfigurationProperties(LumoAuthProperties.class)
public class LumoAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LumoAuth lumoAuth(LumoAuthProperties props, ObjectProvider<TokenProvider> tokenProvider,
                             ObjectProvider<HttpClient> httpClient) {
        LumoAuth.Builder builder = LumoAuth.builder()
            .baseUrl(firstNonBlank(props.getUrl(), System.getenv(LumoAuth.ENV_BASE_URL)))
            .orgId(firstNonBlank(props.getOrgId(), System.getenv(LumoAuth.ENV_ORG_ID)))
            .apiKey(firstNonBlank(props.getApiKey(), System.getenv(LumoAuth.ENV_API_KEY)))
            .timeout(props.getTimeout())
            .skipCertValidation(props.isSkipCertValidation())
            .userAgent(userAgent());
        TokenProvider provider = tokenProvider.getIfAvailable();
        if (provider != null) {
            builder.tokenProvider(provider);
        }
        HttpClient client = httpClient.getIfAvailable();
        if (client != null) {
            builder.httpClient(client);
        }
        return builder.withoutCredential().build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "lumoauth.agent", name = "client-id")
    public LumoAgent lumoAgent(LumoAuthProperties props, ObjectProvider<HttpClient> httpClient) {
        LumoAgent.Builder builder = LumoAgent.builder()
            .baseUrl(props.getUrl())
            .orgId(props.getOrgId())
            .clientId(props.getAgent().getClientId())
            .clientSecret(props.getAgent().getClientSecret())
            .scopes(props.getAgent().getScopes())
            .redirectUri(props.getAgent().getRedirectUri())
            .timeout(props.getTimeout())
            .skipCertValidation(props.isSkipCertValidation())
            .userAgent(userAgent());
        HttpClient client = httpClient.getIfAvailable();
        if (client != null) {
            builder.httpClient(client);
        }
        return builder.build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "lumoauth.aauth", name = "agent-identifier")
    public AAuthClient aauthClient(LumoAuthProperties props, ObjectProvider<HttpClient> httpClient) {
        AAuthClient.Builder builder = AAuthClient.builder()
            .agentIdentifier(props.getAauth().getAgentIdentifier())
            .privateKeyPem(props.getAauth().getPrivateKeyPem())
            .kid(props.getAauth().getKid())
            .baseUrl(props.getUrl())
            .orgId(props.getOrgId())
            .timeout(props.getTimeout())
            .skipCertValidation(props.isSkipCertValidation());
        HttpClient client = httpClient.getIfAvailable();
        if (client != null) {
            builder.httpClient(client);
        }
        return builder.build();
    }

    static String userAgent() {
        return io.lumoauth.Version.userAgent() + " spring-boot-starter";
    }

    static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
