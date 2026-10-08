package io.lumoauth.web;

import io.lumoauth.LumoAuth;
import io.lumoauth.errors.LumoAuthAuthenticationException;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthorizationCodeFlowTest {

    private final FakeServer server = new FakeServer();
    private final LumoAuth lumo = LumoAuth.builder().baseUrl(server.url()).orgId("acme").apiKey(null).withoutCredential().build();
    private final AuthorizationCodeFlow flow = AuthorizationCodeFlow.builder(lumo, "cid", "https://app/auth/callback").clientSecret("sec").build();

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void startAndComplete() {
        AuthorizationCodeFlow.PendingLogin login = flow.start("/dashboard");
        assertThat(login.authorizationUrl()).contains("code_challenge=" + Pkce.challenge(login.codeVerifier())).contains("state=" + login.state());
        assertThat(login.returnTo()).isEqualTo("/dashboard");
        assertThat(flow.start("//evil.com").returnTo()).isEqualTo("/");
        assertThat(flow.start("https://evil.com").returnTo()).isEqualTo("/");

        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "A", "refresh_token", "R", "expires_in", 60)));
        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "u1", "email", "ada@acme.com")));
        AuthorizationCodeFlow.SignedIn user = flow.complete(login, Map.of("code", "c", "state", login.state()));
        assertThat(user.user().email()).isEqualTo("ada@acme.com");
        assertThat(user.expired()).isFalse();
        assertThat(server.requests().get(0).form()).containsEntry("code_verifier", login.codeVerifier()).containsEntry("client_secret", "sec");
        assertThat(server.requests().get(1).header("Authorization")).isEqualTo("Bearer A");

        assertThatThrownBy(() -> flow.complete(login, Map.of("code", "c", "state", "wrong"))).isInstanceOf(LumoAuthAuthenticationException.class).hasMessageContaining("CSRF");
        assertThatThrownBy(() -> flow.complete(login, Map.of("error", "access_denied", "error_description", "no"))).hasMessage("access_denied: no");
        assertThatThrownBy(() -> flow.complete(null, Map.of())).hasMessageContaining("no login in progress");

        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "A2", "expires_in", 60)));
        AuthorizationCodeFlow.SignedIn refreshed = flow.refresh(user).orElseThrow();
        assertThat(refreshed.tokens().accessToken()).isEqualTo("A2");
        assertThat(refreshed.tokens().refreshToken()).isEqualTo("R"); // not rotated
        server.on("/orgs/acme/api/v1/oauth/revoke", Reply.empty(500));
        flow.revoke(refreshed); // best effort, never throws

        server.on("/api/v1/authz/check", Reply.json(Map.of("allowed", true)));
        assertThat(flow.clientFor(refreshed).permissions().check("x")).isTrue();
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer A2");
    }

    @Test
    void pkce() {
        Pkce.Pair pair = Pkce.generate();
        assertThat(pair.verifier()).hasSize(64);
        assertThat(pair.challenge()).isEqualTo(Pkce.challenge(pair.verifier())).hasSize(43);
        assertThat(Pkce.randomToken(32)).hasSize(43);
    }
}
