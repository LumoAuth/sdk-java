package io.lumoauth.spring;

import io.lumoauth.spring.support.FakeServer;
import io.lumoauth.spring.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** ABAC checks run under the user's access token, never the API key (LumoAuth refuses API keys on ABAC). */
class LumoAuthAbacUserTokenTest {

    private static final String ABAC = "/orgs/acme/api/v1/abac/check";

    private final FakeServer server = new FakeServer();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(LumoAuthAutoConfiguration.class, LumoAuthSecurityAutoConfiguration.class))
        .withPropertyValues("lumoauth.url=" + server.url(), "lumoauth.org-id=acme", "lumoauth.api-key=k");

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        server.close();
    }

    private ClientRegistration registration() {
        return ClientRegistration.withRegistrationId("lumoauth")
            .clientId("cid")
            .clientSecret("sec")
            .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("openid", "abac:read")
            .authorizationUri(server.url() + "/orgs/acme/api/v1/oauth/authorize")
            .tokenUri(server.url() + "/orgs/acme/api/v1/oauth/token")
            .userInfoUri(server.url() + "/orgs/acme/api/v1/oauth/userinfo")
            .userNameAttributeName("sub")
            .build();
    }

    private static OAuth2AuthenticationToken oidcLogin() {
        DefaultOAuth2User user = new DefaultOAuth2User(List.of(), Map.of("sub", "42"), "sub");
        return new OAuth2AuthenticationToken(user, List.of(), "lumoauth");
    }

    private ApplicationContextRunner withClients(ClientRegistrationRepository registrations, OAuth2AuthorizedClientService service) {
        return runner.withBean(ClientRegistrationRepository.class, () -> registrations)
            .withBean(OAuth2AuthorizedClientService.class, () -> service);
    }

    private static void signIn(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void assertAbacSentBearer(String token) {
        assertThat(server.last().path()).isEqualTo(ABAC);
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer " + token);
        assertThat(server.last().header("X-API-Key")).isNull();
    }

    @Test
    void oidcLoginSendsTheAuthorizedClientAccessToken() {
        server.on(ABAC, Reply.json(Map.of("allowed", true)));
        server.on("/api/v1/authz/check", Reply.json(Map.of("allowed", true)));
        InMemoryClientRegistrationRepository registrations = new InMemoryClientRegistrationRepository(registration());
        InMemoryOAuth2AuthorizedClientService service = new InMemoryOAuth2AuthorizedClientService(registrations);
        OAuth2AuthenticationToken login = oidcLogin();
        service.saveAuthorizedClient(new OAuth2AuthorizedClient(registration(), "42",
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "USER_AT", Instant.now(), Instant.now().plusSeconds(300))), login);

        withClients(registrations, service).run(context -> {
            assertThat(context).hasSingleBean(UserAccessTokenResolver.class);
            signIn(login);
            PermissionEvaluator evaluator = context.getBean(PermissionEvaluator.class);
            assertThat(evaluator.hasPermission(login, "d1", "document", "read")).isTrue();
            assertAbacSentBearer("USER_AT");
            assertThat(server.last().json()).containsEntry("resourceId", "d1");
            assertThat(context.getBean("lumo", LumoAuthorization.class).abac("document", "read", "d2")).isTrue();
            assertAbacSentBearer("USER_AT");

            // Permission checks still use the API key and name the user.
            assertThat(context.getBean("lumo", LumoAuthorization.class).can("doc.edit")).isTrue();
            assertThat(server.last().header("X-API-Key")).isEqualTo("k");
            assertThat(server.last().header("Authorization")).isNull();
            assertThat(server.last().json()).containsEntry("subject", Map.of("type", "user", "id", "42"));
        });
    }

    @Test
    void oidcLoginInsideAServletRequestUsesTheAuthorizedClientRepository() {
        server.on(ABAC, Reply.json(Map.of("allowed", true)));
        InMemoryClientRegistrationRepository registrations = new InMemoryClientRegistrationRepository(registration());
        InMemoryOAuth2AuthorizedClientService service = new InMemoryOAuth2AuthorizedClientService(registrations);
        OAuth2AuthenticationToken login = oidcLogin();
        service.saveAuthorizedClient(new OAuth2AuthorizedClient(registration(), "42",
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "REQ_AT", Instant.now(), Instant.now().plusSeconds(300))), login);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));

        withClients(registrations, service)
            .withBean(OAuth2AuthorizedClientRepository.class, () -> new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(service))
            .run(context -> {
                signIn(login);
                assertThat(context.getBean(PermissionEvaluator.class).hasPermission(login, "d1", "document", "read")).isTrue();
                assertAbacSentBearer("REQ_AT");
            });
    }

    @Test
    void expiredOidcTokenIsRefreshed() {
        server.on(ABAC, Reply.json(Map.of("allowed", true)));
        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "NEW_AT", "token_type", "Bearer",
            "expires_in", 300, "refresh_token", "R2")));
        InMemoryClientRegistrationRepository registrations = new InMemoryClientRegistrationRepository(registration());
        InMemoryOAuth2AuthorizedClientService service = new InMemoryOAuth2AuthorizedClientService(registrations);
        OAuth2AuthenticationToken login = oidcLogin();
        service.saveAuthorizedClient(new OAuth2AuthorizedClient(registration(), "42",
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "OLD_AT", Instant.now().minusSeconds(600), Instant.now().minusSeconds(300)),
            new OAuth2RefreshToken("R1", Instant.now().minusSeconds(600))), login);

        withClients(registrations, service).run(context -> {
            signIn(login);
            assertThat(context.getBean("lumo", LumoAuthorization.class).abac("document", "read", "d1")).isTrue();
            assertAbacSentBearer("NEW_AT");
            assertThat(server.requests()).extracting(FakeServer.Recorded::path)
                .containsExactly("/orgs/acme/api/v1/oauth/token", ABAC);
        });
    }

    @Test
    void missingOrExpiredOidcTokenDenies() {
        server.on(ABAC, Reply.json(Map.of("allowed", true)));
        InMemoryClientRegistrationRepository registrations = new InMemoryClientRegistrationRepository(registration());
        InMemoryOAuth2AuthorizedClientService service = new InMemoryOAuth2AuthorizedClientService(registrations);
        OAuth2AuthenticationToken login = oidcLogin();

        withClients(registrations, service).run(context -> {
            signIn(login);
            LumoAuthorization lumo = context.getBean("lumo", LumoAuthorization.class);
            assertThat(lumo.abac("document", "read", "d1")).isFalse();
            assertThat(context.getBean(PermissionEvaluator.class).hasPermission(login, "d1", "document", "read")).isFalse();

            service.saveAuthorizedClient(new OAuth2AuthorizedClient(registration(), "42",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "OLD_AT", Instant.now().minusSeconds(600), Instant.now().minusSeconds(300))), login);
            assertThat(lumo.abac("document", "read", "d1")).isFalse();
            assertThat(server.requests()).isEmpty();
        });
    }

    @Test
    void oidcLoginWithoutTheOAuth2ClientBeansDenies() {
        server.on(ABAC, Reply.json(Map.of("allowed", true)));
        runner.run(context -> {
            OAuth2AuthenticationToken login = oidcLogin();
            signIn(login);
            assertThat(context.getBean(PermissionEvaluator.class).hasPermission(login, "d1", "document", "read")).isFalse();
            assertThat(server.requests()).isEmpty();
        });
    }

    @Test
    void bearerRequestsSendTheIncomingToken() {
        server.on(ABAC, Reply.json(Map.of("allowed", true)));
        runner.run(context -> {
            LumoAuthorization lumo = context.getBean("lumo", LumoAuthorization.class);
            OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "OPAQUE", Instant.now(), Instant.now().plusSeconds(60));
            signIn(new BearerTokenAuthentication(new OAuth2IntrospectionAuthenticatedPrincipal("u1", Map.of("sub", "u1"), List.of()), token, List.of()));
            assertThat(lumo.abac("document", "read", "d1")).isTrue();
            assertAbacSentBearer("OPAQUE");

            Jwt jwt = Jwt.withTokenValue("JWT_VALUE").header("alg", "RS256").subject("u1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
            JwtAuthenticationToken jwtAuth = new JwtAuthenticationToken(jwt, List.of());
            signIn(jwtAuth);
            assertThat(context.getBean(PermissionEvaluator.class).hasPermission(jwtAuth, "d1", "document", "read")).isTrue();
            assertAbacSentBearer("JWT_VALUE");
        });
    }

    @Test
    void anOwnResolverReplacesTheDefault() {
        server.on(ABAC, Reply.json(Map.of("allowed", true)));
        runner.withUserConfiguration(OwnResolver.class).run(context -> {
            assertThat(context).hasSingleBean(UserAccessTokenResolver.class);
            signIn(oidcLogin());
            assertThat(context.getBean("lumo", LumoAuthorization.class).abac("document", "read", "d1")).isTrue();
            assertAbacSentBearer("FROM_RESOLVER");
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class OwnResolver {
        @Bean
        UserAccessTokenResolver userAccessTokenResolver() {
            return authentication -> Optional.of("FROM_RESOLVER");
        }
    }
}
