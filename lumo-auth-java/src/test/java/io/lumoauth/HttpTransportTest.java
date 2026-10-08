package io.lumoauth;

import io.lumoauth.errors.LumoAuthApiException;
import io.lumoauth.errors.LumoAuthAuthenticationException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthNetworkException;
import io.lumoauth.errors.LumoAuthNotFoundException;
import io.lumoauth.errors.LumoAuthPermissionDeniedException;
import io.lumoauth.errors.LumoAuthRateLimitException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.model.AgentAskResult;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpTransportTest {

    private final FakeServer server = new FakeServer();

    @AfterEach
    void stop() {
        server.close();
    }

    private LumoAuth client(LumoAuth.Builder builder) {
        return builder.baseUrl(server.url()).orgId("acme").build();
    }

    @Test
    void apiKeyGoesInXApiKeyAndBearerWins() {
        server.on("/api/v1/authz/check", Reply.json(Map.of("allowed", true)));
        client(LumoAuth.builder().apiKey("k-1")).permissions().check("doc.edit");
        FakeServer.Recorded first = server.last();
        assertThat(first.header("X-API-Key")).isEqualTo("k-1");
        assertThat(first.header("Authorization")).isNull();
        assertThat(first.header("User-Agent")).startsWith("lumoauth-java/" + Version.SDK);
        assertThat(first.header("Accept")).isEqualTo("application/json");

        client(LumoAuth.builder().apiKey("k-1").accessToken("t-1")).permissions().check("doc.edit");
        FakeServer.Recorded second = server.last();
        assertThat(second.header("Authorization")).isEqualTo("Bearer t-1");
        assertThat(second.header("X-API-Key")).isNull();
    }

    @Test
    void tokenProviderIsCalledPerRequestAndEmptyFallsBackToApiKey() {
        server.on("/api/v1/authz/check", Reply.json(Map.of("allowed", true)));
        String[] token = {"first"};
        LumoAuth lumo = client(LumoAuth.builder().apiKey("k").tokenProvider(() -> token[0]));
        lumo.permissions().check("p");
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer first");
        token[0] = "";
        lumo.permissions().check("p");
        assertThat(server.last().header("Authorization")).isNull();
        assertThat(server.last().header("X-API-Key")).isEqualTo("k");
    }

    @Test
    void explicitHeadersAndNoAuthSuppressInjection() {
        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "u1")));
        LumoAuth lumo = client(LumoAuth.builder().apiKey("k").header("X-Trace", "abc"));
        lumo.auth().userinfo("user-token");
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer user-token");
        assertThat(server.last().header("X-API-Key")).isNull();
        assertThat(server.last().header("X-Trace")).isEqualTo("abc");

        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "a", "expires_in", 10)));
        lumo.auth().clientCredentials("c", "s", "read");
        FakeServer.Recorded token = server.last();
        assertThat(token.header("Authorization")).isNull();
        assertThat(token.header("X-API-Key")).isNull();
        assertThat(token.header("Content-Type")).isEqualTo("application/x-www-form-urlencoded");
        assertThat(token.form()).containsEntry("grant_type", "client_credentials").containsEntry("scope", "read");
    }

    @Test
    void orgIdIsRequiredForOrgScopedRoutesOnly() {
        server.on("/api/v1/authz/check", Reply.json(Map.of("allowed", true)));
        LumoAuth lumo = LumoAuth.builder().baseUrl(server.url()).orgId(null).apiKey("k").build();
        assertThat(lumo.permissions().check("p")).isTrue();
        assertThatThrownBy(() -> lumo.agents().me())
            .isInstanceOf(LumoAuthConfigException.class)
            .hasMessageContaining("LUMOAUTH_ORG_ID");
        assertThatThrownBy(() -> lumo.orgPath("/x")).isInstanceOf(LumoAuthConfigException.class);
        assertThat(client(LumoAuth.builder().apiKey("k")).orgPath("/admin/users")).isEqualTo("/orgs/acme/api/v1/admin/users");
    }

    @Test
    void credentialIsRequiredUnlessOptedOut() {
        assertThatThrownBy(() -> LumoAuth.builder().baseUrl(server.url()).apiKey(null).build())
            .isInstanceOf(LumoAuthConfigException.class)
            .hasMessageContaining("LUMOAUTH_API_KEY");
        assertThat(LumoAuth.builder().baseUrl(server.url()).apiKey(null).withoutCredential().build()).isNotNull();
    }

    @Test
    void mapsStatusesOntoTheTaxonomy() {
        LumoAuth lumo = client(LumoAuth.builder().apiKey("k"));
        server.on("/e/401", Reply.json(401, Map.of("error", "invalid_token", "error_description", "expired")));
        server.on("/e/403", Reply.json(403, Map.of("message", "nope", "code", "CUSTOM")));
        server.on("/e/404", Reply.text(404, "<html>missing</html>"));
        server.on("/e/429", Reply.json(429, Map.of("detail", "slow down")).header("Retry-After", "2"));
        server.on("/e/500", Reply.empty(500));

        assertThatThrownBy(() -> lumo.request("GET", "/e/401", null, Map.class))
            .isInstanceOf(LumoAuthAuthenticationException.class)
            .hasMessage("expired")
            .satisfies(e -> assertThat(((LumoAuthApiException) e).code()).isEqualTo("invalid_token"));
        assertThatThrownBy(() -> lumo.request("GET", "/e/403", null, Map.class))
            .isInstanceOf(LumoAuthPermissionDeniedException.class)
            .hasMessage("nope")
            .satisfies(e -> {
                LumoAuthApiException api = (LumoAuthApiException) e;
                assertThat(api.code()).isEqualTo("CUSTOM");
                assertThat(api.statusCode()).isEqualTo(403);
                assertThat(api.bodyAsMap()).isPresent();
            });
        assertThatThrownBy(() -> lumo.request("GET", "/e/404", null, Map.class))
            .isInstanceOf(LumoAuthNotFoundException.class)
            .hasMessage("HTTP 404 - <html>missing</html>")
            .satisfies(e -> assertThat(((LumoAuthApiException) e).code()).isEqualTo("NOT_FOUND"));
        assertThatThrownBy(() -> lumo.request("GET", "/e/429", null, Map.class))
            .isInstanceOf(LumoAuthRateLimitException.class)
            .satisfies(e -> assertThat(((LumoAuthRateLimitException) e).retryAfter()).contains(Duration.ofSeconds(2)));
        assertThatThrownBy(() -> lumo.request("GET", "/e/500", null, Map.class))
            .isInstanceOf(LumoAuthApiException.class)
            .isNotInstanceOf(LumoAuthAuthenticationException.class)
            .hasMessage("HTTP 500 Internal Server Error")
            .satisfies(e -> assertThat(((LumoAuthApiException) e).code()).isEqualTo("API_ERROR"));
    }

    @Test
    void transportFailuresAreNetworkErrors() {
        LumoAuth lumo = LumoAuth.builder().baseUrl("http://127.0.0.1:1").apiKey("k").timeout(Duration.ofSeconds(2)).build();
        assertThatThrownBy(() -> lumo.request("GET", "/x", null, Map.class)).isInstanceOf(LumoAuthNetworkException.class);
    }

    @Test
    void decodesRecordsWithRawAndRejectsMalformedJson() {
        server.on("/ask", Reply.json(Map.of("allowed", true, "action", "a", "future_field", 7, "context", Map.of("k", "v"))));
        server.on("/bad", Reply.text(200, "{not json"));
        LumoAuth lumo = client(LumoAuth.builder().apiKey("k"));
        AgentAskResult result = lumo.request("POST", "/ask", Map.of("action", "a"), AgentAskResult.class);
        assertThat(result.allowed()).isTrue();
        assertThat(result.raw()).containsEntry("future_field", 7);
        assertThat(result.context()).containsEntry("k", "v");
        assertThat(server.last().json()).containsEntry("action", "a");
        assertThatThrownBy(() -> lumo.request("GET", "/bad", null, Map.class)).isInstanceOf(LumoAuthValidationException.class);
    }

    @Test
    void emptyBodiesDecodeToNull() {
        server.on("/empty", Reply.empty(204));
        LumoAuth lumo = client(LumoAuth.builder().apiKey("k"));
        assertThat(lumo.request("DELETE", "/empty", null, Map.class)).isNull();
        assertThat(lumo.requestMap("DELETE", "/empty", null)).isEmpty();
    }

    @Test
    void apiClientConfigCarriesExactlyOneCredential() {
        LumoAuth withKey = client(LumoAuth.builder().apiKey("k"));
        assertThat(withKey.apiClientConfig().defaultHeaders()).containsExactly(Map.entry("X-API-Key", "k"));
        assertThat(withKey.apiClientConfig().basePath()).isEqualTo(server.url());
        LumoAuth withToken = client(LumoAuth.builder().apiKey("k").accessToken("t"));
        assertThat(withToken.apiClientConfig().defaultHeaders()).containsExactly(Map.entry("Authorization", "Bearer t"));
        assertThatThrownBy(() -> client(LumoAuth.builder().apiKey(null).withoutCredential()).apiClientConfig())
            .isInstanceOf(LumoAuthConfigException.class);
    }

    @Test
    void retryAfterParsesSecondsAndDates() {
        assertThat(HttpTransport.parseRetryAfterForTest("1.5")).isEqualTo(Duration.ofMillis(1500));
        assertThat(HttpTransport.parseRetryAfterForTest("-1")).isNull();
        assertThat(HttpTransport.parseRetryAfterForTest("garbage")).isNull();
        assertThat(HttpTransport.parseRetryAfterForTest("Wed, 21 Oct 2015 07:28:00 GMT")).isNull(); // in the past
    }

    @Test
    void queryParametersAreAppended() {
        server.on("/q", Reply.json(List.of()));
        LumoAuth lumo = client(LumoAuth.builder().apiKey("k"));
        lumo.transport().sendNode("GET", "/q?a=1", ApiRequest.empty().query("type", "user"));
        assertThat(server.last().query()).isEqualTo("a=1&type=user");
    }
}
