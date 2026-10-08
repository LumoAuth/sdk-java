package io.lumoauth.spring;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Map;

/**
 * Browser sign-in through Spring Security's OIDC login, enabled by
 * {@code lumoauth.login.client-id}:
 * <ul>
 *   <li>a {@link ClientRegistration} named {@code lumoauth} (login at
 *       {@code /oauth2/authorization/lumoauth}, callback at
 *       {@code /login/oauth2/code/lumoauth}) built from the known LumoAuth
 *       endpoints, so no discovery request is made at startup;</li>
 *   <li>a default {@link SecurityFilterChain} that requires sign-in everywhere
 *       except {@code lumoauth.login.permit-all} and accepts LumoAuth bearer
 *       tokens when the introspector is present. It backs off when the app
 *       defines its own chain, or {@code lumoauth.login.default-filter-chain=false}.</li>
 * </ul>
 */
@AutoConfiguration(after = LumoAuthSecurityAutoConfiguration.class,
    beforeName = {
        "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration"
    })
@ConditionalOnClass({ClientRegistrationRepository.class, SecurityFilterChain.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "lumoauth.login", name = "client-id")
public class LumoAuthLoginAutoConfiguration {

    /** The LumoAuth client registration for the configured organization. */
    public static ClientRegistration clientRegistration(LumoAuthProperties props) {
        String issuer = props.issuer();
        LumoAuthProperties.Login login = props.getLogin();
        boolean confidential = login.getClientSecret() != null && !login.getClientSecret().isBlank();
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(login.getRegistrationId())
            .clientId(login.getClientId())
            .clientSecret(confidential ? login.getClientSecret() : null)
            .clientAuthenticationMethod(confidential ? ClientAuthenticationMethod.CLIENT_SECRET_BASIC : ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope(login.getScopes())
            .authorizationUri(issuer + "/oauth/authorize")
            .tokenUri(issuer + "/oauth/token")
            .userInfoUri(issuer + "/oauth/userinfo")
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .jwkSetUri(issuer + "/.well-known/jwks.json")
            .issuerUri(issuer)
            .providerConfigurationMetadata(Map.of("end_session_endpoint", issuer + "/oauth/logout"))
            .clientName("LumoAuth");
        return builder.build();
    }

    @Bean
    @ConditionalOnMissingBean(ClientRegistrationRepository.class)
    public InMemoryClientRegistrationRepository lumoAuthClientRegistrationRepository(LumoAuthProperties props) {
        return new InMemoryClientRegistrationRepository(clientRegistration(props));
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @ConditionalOnProperty(prefix = "lumoauth.login", name = "default-filter-chain", havingValue = "true", matchIfMissing = true)
    public SecurityFilterChain lumoAuthSecurityFilterChain(HttpSecurity http, LumoAuthProperties props,
                                                           ObjectProvider<OpaqueTokenIntrospector> introspector) throws Exception {
        LumoAuthProperties.Login login = props.getLogin();
        RequestMatcher[] permitAll = login.getPermitAll().stream()
            .map(pattern -> PathPatternRequestMatcher.withDefaults().matcher(pattern))
            .toArray(RequestMatcher[]::new);
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(permitAll).permitAll()
                .anyRequest().authenticated())
            .oauth2Login(oauth2 -> oauth2.defaultSuccessUrl(login.getSuccessUrl(), false));
        OpaqueTokenIntrospector tokenIntrospector = introspector.getIfAvailable();
        if (tokenIntrospector != null) {
            http.oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(opaque -> opaque.introspector(tokenIntrospector)));
        }
        return http.build();
    }
}
