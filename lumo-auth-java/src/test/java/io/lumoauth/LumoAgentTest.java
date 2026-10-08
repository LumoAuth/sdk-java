package io.lumoauth;

import io.lumoauth.errors.LumoAuthBudgetExceededException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthPermissionDeniedException;
import io.lumoauth.model.RegisterAgentRequest;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LumoAgentTest {

    private final FakeServer server = new FakeServer();
    private final LumoAgent agent = LumoAgent.builder().baseUrl(server.url() + "/").orgId("acme")
        .clientId("cid").clientSecret("sec").scopes("a", "b").build();

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void requiresCredentials() {
        assertThatThrownBy(() -> LumoAgent.builder().baseUrl(server.url()).clientId("x").clientSecret(null).build())
            .isInstanceOf(LumoAuthConfigException.class)
            .hasMessageContaining("AGENT_CLIENT_ID");
        assertThat(agent.baseUrl()).isEqualTo(server.url());
        assertThat(agent.clientId()).isEqualTo("cid");
        assertThat(agent.orgId()).isEqualTo("acme");
    }

    @Test
    void authenticatesLazilyCachesAndRefreshesNearExpiry() throws Exception {
        server.queue("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "T1", "expires_in", 3600, "scope", "a b")),
            Reply.json(Map.of("access_token", "T2", "expires_in", 30)),
            Reply.json(Map.of("access_token", "T3", "expires_in", 3600)));
        server.on("/orgs/acme/api/v1/agents/ask", Reply.json(Map.of("allowed", true)));

        assertThat(agent.isAllowed("x", Map.of("id", 1))).isTrue();
        assertThat(server.requests().get(0).path()).endsWith("/oauth/token");
        assertThat(server.requests().get(0).form()).containsEntry("grant_type", "client_credentials").containsEntry("scope", "a b")
            .containsEntry("client_id", "cid").containsEntry("client_secret", "sec");
        assertThat(server.requests().get(1).header("Authorization")).isEqualTo("Bearer T1");
        assertThat(agent.tokenScopes()).containsExactly("a", "b");

        // Cached: no second token request.
        agent.ask("y");
        assertThat(server.requests()).hasSize(3);
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer T1");

        // Concurrent callers after an explicit re-authentication share the cache.
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Future<String>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < 16; i++) {
            futures.add(pool.submit(agent::accessToken));
        }
        for (Future<String> f : futures) {
            assertThat(f.get(5, TimeUnit.SECONDS)).isEqualTo("T1");
        }
        pool.shutdown();

        // A token within the refresh buffer of expiry is refreshed on the next call.
        assertThat(agent.authenticate("c")).isEqualTo("T2");
        assertThat(server.last().form()).containsEntry("scope", "c");
        assertThat(agent.accessToken()).isEqualTo("T3"); // 30s - 60s buffer => already stale
    }

    @Test
    void capabilityAndBudgetGuards() {
        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "T", "expires_in", 3600)));
        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "ag", "agent_id", "ag", "capabilities", List.of("tool:search"),
            "budget_policy", Map.of("max_tokens_per_day", 100, "tokens_used_today", 100))));
        agent.requireCapability("tool:search");
        assertThat(agent.hasCapability("tool:email")).isFalse();
        assertThatThrownBy(() -> agent.requireCapability("tool:email"))
            .isInstanceOf(LumoAuthPermissionDeniedException.class)
            .satisfies(e -> assertThat(((LumoAuthPermissionDeniedException) e).statusCode()).isZero())
            .hasMessageContaining("tool:email");
        assertThatThrownBy(agent::checkBudget).isInstanceOf(LumoAuthBudgetExceededException.class)
            .satisfies(e -> assertThat(((LumoAuthBudgetExceededException) e).budget().maxTokensPerDay()).isEqualTo(100));
        // Info is cached: one userinfo call so far.
        assertThat(server.requests().stream().filter(r -> r.path().endsWith("/userinfo")).count()).isEqualTo(1);
        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "ag", "capabilities", List.of())));
        assertThat(agent.info(true).capabilities()).isEmpty();
        agent.checkBudget(); // no policy => never exhausted

        server.on("/orgs/acme/api/v1/agents/me", Reply.json(Map.of("identity", Map.of("id", "ag"))));
        assertThat(agent.identity().id()).contains("ag");
        server.on("/orgs/acme/api/v1/agents/register", Reply.json(Map.of("agent_id", "ag")));
        agent.register(RegisterAgentRequest.builder("Agent", null).build());
        assertThat(server.last().json()).containsEntry("client_id", "cid");
        assertThat(agent.client().permissions()).isSameAs(agent.permissions());
    }
}
