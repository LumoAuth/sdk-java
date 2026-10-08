package io.lumoauth;

import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DelegationChainTest {

    private final FakeServer server = new FakeServer();
    private final ConfidentialClient agent = new ConfidentialClient() {
        public String baseUrl() { return server.url(); }
        public String orgId() { return "acme"; }
        public String accessToken() { return "AGENT"; }
        public String clientId() { return "cid"; }
        public String clientSecret() { return "sec"; }
    };
    private final DelegationChain chain = new DelegationChain(agent, "https://agent/cb");

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void consentExchangeRequestAndRevoke() {
        String url = chain.consentUrl("s1", List.of("read:documents"));
        assertThat(url).contains("client_id=cid").contains("state=session%3As1").contains("prompt=consent");
        assertThatThrownBy(() -> new DelegationChain(agent, null).consentUrl("s1", List.of())).isInstanceOf(LumoAuthConfigException.class);

        server.queue("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "USER", "refresh_token", "UR", "expires_in", 3600)),
            Reply.json(Map.of("access_token", "DELEGATED")));
        chain.handleConsentCallback("s1", "code-1");
        assertThat(server.last().form()).containsEntry("code", "code-1").containsEntry("redirect_uri", "https://agent/cb").containsEntry("client_secret", "sec");
        assertThat(chain.activeSessions()).containsExactly("s1");
        assertThat(chain.hasDelegation("s1")).isFalse();

        server.on("/orgs/acme/api/v1/docs", Reply.json(Map.of("count", 1)));
        Map<?, ?> docs = chain.request("s1", "GET", "/orgs/acme/api/v1/docs", null, Map.class);
        assertThat(docs.get("count")).isEqualTo(1);
        assertThat(server.requests().get(1).form()).containsEntry("subject_token", "USER").containsEntry("actor_token", "AGENT");
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer DELEGATED");
        assertThat(chain.hasDelegation("s1")).isTrue();
        chain.request("s1", "GET", "/orgs/acme/api/v1/docs", null, Map.class);
        assertThat(server.requests().stream().filter(r -> r.path().endsWith("/oauth/token")).count()).isEqualTo(2); // cached

        server.on("/orgs/acme/api/v1/oauth/revoke", Reply.empty(200));
        chain.revoke("s1");
        assertThat(server.last().form()).containsEntry("token", "UR").containsEntry("token_type_hint", "refresh_token");
        assertThat(chain.activeSessions()).isEmpty();
        assertThatThrownBy(() -> chain.exchange("s1")).isInstanceOf(LumoAuthConfigException.class).hasMessageContaining("consent flow");
    }

    @Test
    void setUserTokenAndSubAgentDelegation() {
        chain.setUserToken("s2", "USER2");
        server.queue("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "D2")), Reply.json(Map.of("access_token", "SUB")));
        assertThat(chain.delegateToSubAgent("s2", "SUBAGENT", "read")).isEqualTo("SUB");
        assertThat(server.last().form()).containsEntry("subject_token", "D2").containsEntry("actor_token", "SUBAGENT").containsEntry("scope", "read");
        chain.revoke("s2"); // no refresh token: nothing to revoke server-side
        assertThat(server.requests()).hasSize(2);
        assertThatThrownBy(() -> chain.setUserToken("", "x")).isInstanceOf(LumoAuthValidationException.class);
    }

    @Test
    void depthErrorsAreExplained() {
        chain.setUserToken("s3", "U");
        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(400, Map.of("error", "delegation_depth_exceeded", "max_depth", 3)));
        assertThatThrownBy(() -> chain.exchange("s3")).isInstanceOf(LumoAuthValidationException.class).hasMessageContaining("maximum depth: 3");
        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(400, Map.of("error", "invalid_grant", "error_description", "bad")));
        assertThatThrownBy(() -> chain.exchange("s3")).hasMessage("token exchange failed: bad");
    }
}
