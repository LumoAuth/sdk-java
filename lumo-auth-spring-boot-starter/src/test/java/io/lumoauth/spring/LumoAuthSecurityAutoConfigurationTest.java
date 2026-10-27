package io.lumoauth.spring;

import io.lumoauth.spring.support.FakeServer;
import io.lumoauth.spring.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LumoAuthSecurityAutoConfigurationTest {

    private final FakeServer server = new FakeServer();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, LumoAuthAutoConfiguration.class, LumoAuthSecurityAutoConfiguration.class))
        .withPropertyValues("lumoauth.url=" + server.url(), "lumoauth.org-id=acme", "lumoauth.api-key=k");

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
        server.close();
    }

    @Test
    void introspectorResolvesUserinfoToAPrincipal() {
        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "u1", "email", "a@b", "roles", List.of("admin"),
            "capabilities", List.of("tool:x"))));
        runner.run(context -> {
            assertThat(context).hasSingleBean(OpaqueTokenIntrospector.class).hasBean("lumo").hasSingleBean(PermissionEvaluator.class);
            OAuth2AuthenticatedPrincipal principal = context.getBean(OpaqueTokenIntrospector.class).introspect("TOKEN");
            assertThat(principal.getName()).isEqualTo("u1");
            assertThat(principal.getAttributes()).containsEntry("email", "a@b");
            assertThat(principal.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_admin", "CAPABILITY_tool:x");
            assertThat(server.last().header("Authorization")).isEqualTo("Bearer TOKEN");
            assertThat(server.last().header("X-API-Key")).isNull();

            server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(401, Map.of("error", "invalid_token")));
            assertThatThrownBy(() -> context.getBean(OpaqueTokenIntrospector.class).introspect("bad")).isInstanceOf(BadOpaqueTokenException.class);
            server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(500, Map.of()));
            assertThatThrownBy(() -> context.getBean(OpaqueTokenIntrospector.class).introspect("bad"))
                .isInstanceOf(OAuth2IntrospectionException.class).isNotInstanceOf(BadOpaqueTokenException.class);
        });
    }

    @Test
    void permissionsCanBecomeAuthorities() {
        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "u1")));
        server.on("/api/v1/authz/permissions", Reply.json(Map.of("permissions", List.of(Map.of("slug", "doc.edit")))));
        runner.withPropertyValues("lumoauth.security.permissions-as-authorities=true").run(context -> {
            OAuth2AuthenticatedPrincipal principal = context.getBean(OpaqueTokenIntrospector.class).introspect("TOKEN");
            assertThat(principal.getAuthorities()).extracting(Object::toString).containsExactly("PERMISSION_doc.edit");
            assertThat(server.last().header("Authorization")).isEqualTo("Bearer TOKEN");
        });
    }

    @Test
    void bearerTokensCanBeDisabled() {
        runner.withPropertyValues("lumoauth.security.bearer-tokens=false").run(context ->
            assertThat(context).doesNotHaveBean(OpaqueTokenIntrospector.class).hasBean("lumo"));
    }

    @Test
    void lumoBeanChecksUnderTheBearerTokenOrTheApiKey() {
        server.on("/api/v1/authz/check", req -> Reply.json(Map.of("allowed", "Bearer USER".equals(req.header("Authorization")))));
        runner.run(context -> {
            LumoAuthorization lumo = context.getBean("lumo", LumoAuthorization.class);
            assertThatThrownBy(() -> lumo.can("doc.edit")).isInstanceOf(AuthenticationCredentialsNotFoundException.class);

            OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "USER", Instant.now(), Instant.now().plusSeconds(60));
            OAuth2AuthenticatedPrincipal principal = new org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal(
                "u1", Map.of("sub", "u1"), List.of());
            SecurityContextHolder.getContext().setAuthentication(new BearerTokenAuthentication(principal, token, List.of()));
            assertThat(lumo.can("doc.edit")).isTrue();
            assertThat(server.last().header("Authorization")).isEqualTo("Bearer USER");
            assertThat(server.last().json()).doesNotContainKey("user_id").doesNotContainKey("subject");

            TestingAuthenticationToken form = new TestingAuthenticationToken("42", "pw");
            form.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(form);
            assertThat(lumo.can("doc.edit")).isFalse();
            assertThat(server.last().header("X-API-Key")).isEqualTo("k");
            assertThat(server.last().json()).containsEntry("subject", Map.of("type", "user", "id", "42"))
                .doesNotContainKey("user_id");

            TestingAuthenticationToken agentLogin = new TestingAuthenticationToken("agent_agt_7", "pw");
            agentLogin.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(agentLogin);
            lumo.can("doc.edit");
            assertThat(server.last().json()).containsEntry("subject", Map.of("type", "agent", "id", "agt_7"));
            SecurityContextHolder.getContext().setAuthentication(form);

            server.on("/api/v1/authz/zanzibar/check", Reply.json(Map.of("allowed", true)));
            assertThat(lumo.isViewer("document:1")).isTrue();
            assertThat(server.last().json()).containsEntry("subject", "user:42");
            assertThat(context.getBean(PermissionEvaluator.class).hasPermission(form, "document:1", "viewer")).isTrue();
            // A form login has no user access token, and ABAC refuses the API key: deny without a request.
            server.on("/orgs/acme/api/v1/abac/check", Reply.json(Map.of("allowed", true)));
            int before = server.requests().size();
            assertThat(context.getBean(PermissionEvaluator.class).hasPermission(form, "d1", "document", "read")).isFalse();
            assertThat(server.requests()).hasSize(before);
        });
    }

    @Test
    void requirePermissionGuardsBeanMethods() {
        server.on("/api/v1/authz/check", req -> Reply.json(Map.of("allowed", "doc.edit".equals(req.json().get("permission")))));
        server.on("/api/v1/authz/check-any", Reply.json(Map.of("allowed", true)));
        runner.withUserConfiguration(ServiceConfig.class).run(context -> {
            TestingAuthenticationToken auth = new TestingAuthenticationToken("42", "pw");
            auth.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(auth);
            DocumentService service = context.getBean(DocumentService.class);
            assertThat(service.edit("d1")).isEqualTo("edited d1");
            assertThatThrownBy(() -> service.delete("d1")).isInstanceOf(AccessDeniedException.class).hasMessageContaining("doc.delete");
            assertThat(service.publish("d1")).isEqualTo("published d1");
            assertThat(server.last().json()).containsEntry("permissions", List.of("doc.edit", "doc.admin"));
            assertThat(service.read("d1")).isEqualTo("read d1");
            SecurityContextHolder.clearContext();
            assertThatThrownBy(() -> service.edit("d1")).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class ServiceConfig {
        @Bean
        DocumentService documentService() {
            return new DocumentService();
        }
    }

    static class DocumentService {
        @RequirePermission("doc.edit")
        public String edit(String id) {
            return "edited " + id;
        }

        @RequirePermission("doc.delete")
        public String delete(String id) {
            return "deleted " + id;
        }

        @RequirePermission(value = {"doc.edit", "doc.admin"}, mode = RequirePermission.Mode.ANY)
        public String publish(String id) {
            return "published " + id;
        }

        public String read(String id) {
            return "read " + id;
        }
    }
}
