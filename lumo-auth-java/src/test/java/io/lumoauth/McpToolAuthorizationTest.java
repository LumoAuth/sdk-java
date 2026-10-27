package io.lumoauth;

import io.lumoauth.errors.LumoAuthApiException;
import io.lumoauth.errors.LumoAuthAuthenticationException;
import io.lumoauth.errors.LumoAuthNotFoundException;
import io.lumoauth.errors.LumoAuthPermissionDeniedException;
import io.lumoauth.errors.LumoAuthRateLimitException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.model.AgentMcpToolDecision;
import io.lumoauth.model.McpToolDecision;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@code mcp.authorizeTool} and {@code agents.authorizeMcpTool}: decisions, errors and validation. */
class McpToolAuthorizationTest {

    private static final String SERVER = "mcp_0123456789abcdef01234567";
    private static final String TOOL_PATH = "/orgs/acme/api/v1/mcp/servers/" + SERVER + "/tools/authorize";
    private static final String AGENT_PATH = "/orgs/acme/api/v1/agents/me/mcp/authorize";

    private final FakeServer server = new FakeServer();
    private final LumoAuth lumo = LumoAuth.builder().baseUrl(server.url()).orgId("acme")
        .apiKey(null).accessToken("MCP_CC").build();

    @AfterEach
    void stop() {
        server.close();
    }

    private static Map<String, Object> toolBody(boolean allowed) {
        return Map.of("allowed", allowed, "subject", Map.of("type", "user", "id", "u-1"),
            "resource", Map.of("type", "mcp_tool", "id", SERVER + "/search"));
    }

    private static Map<String, Object> agentBody(boolean allowed) {
        return Map.of("allowed", allowed, "agent_id", "agt_1",
            "resource", Map.of("type", "mcp_tool", "id", SERVER + "/search"));
    }

    @Test
    void authorizeToolAllows() {
        server.on(TOOL_PATH, Reply.json(toolBody(true)));
        McpToolDecision d = lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search");
        assertThat(d.allowed()).isTrue();
        assertThat(d.subject()).isEqualTo(new McpToolDecision.Subject("user", "u-1"));
        assertThat(d.resource()).isEqualTo(new McpToolDecision.Resource("mcp_tool", SERVER + "/search"));
        assertThat(d.raw()).containsEntry("allowed", true);

        FakeServer.Recorded req = server.only();
        assertThat(req.method()).isEqualTo("POST");
        assertThat(req.path()).isEqualTo(TOOL_PATH);
        assertThat(req.header("Authorization")).isEqualTo("Bearer MCP_CC");
        assertThat(req.header("X-API-Key")).isNull();
        assertThat(req.json()).isEqualTo(Map.of("subject", Map.of("type", "user", "id", "u-1"), "tool", "search"));
    }

    @Test
    void authorizeToolDenyIsADecision() {
        server.on(TOOL_PATH, Reply.json(403, toolBody(false)));
        McpToolDecision d = lumo.mcp().authorizeTool(SERVER, "agent", "agent_agt_1", "search");
        assertThat(d.allowed()).isFalse();
        assertThat(d.resource().id()).isEqualTo(SERVER + "/search");
        assertThat(server.only().json()).containsEntry("subject", Map.of("type", "agent", "id", "agent_agt_1"));
    }

    @Test
    void authorizeToolEncodesTheServerId() {
        String path = "/orgs/acme/api/v1/mcp/servers/mcp%20a%3F/tools/authorize";
        server.on(path, Reply.json(toolBody(true)));
        assertThat(lumo.mcp().authorizeTool("mcp a?", "user", "u-1", "search").allowed()).isTrue();
        assertThat(server.only().path()).isEqualTo(path);
    }

    @Test
    void authorizeToolErrorsThrow() {
        server.queue(TOOL_PATH,
            Reply.json(403, Map.of("error", "insufficient_scope", "error_description", "mcp:authorize is required")),
            Reply.json(403, Map.of("error", "forbidden")),
            Reply.json(403, Map.of("error", "forbidden", "allowed", true)),
            Reply.json(404, Map.of("error", "not_found")),
            Reply.json(401, Map.of("error", "invalid_token")),
            Reply.json(400, Map.of("error", "invalid_request")),
            Reply.json(429, Map.of("error", "too_many_requests")).header("Retry-After", "7"));
        assertThatThrownBy(() -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search"))
            .isInstanceOf(LumoAuthPermissionDeniedException.class)
            .satisfies(e -> assertThat(((LumoAuthApiException) e).code()).isEqualTo("insufficient_scope"));
        assertThatThrownBy(() -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search"))
            .isInstanceOf(LumoAuthPermissionDeniedException.class);
        assertThatThrownBy(() -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search"))
            .isInstanceOf(LumoAuthPermissionDeniedException.class);
        assertThatThrownBy(() -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search"))
            .isInstanceOf(LumoAuthNotFoundException.class);
        assertThatThrownBy(() -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search"))
            .isInstanceOf(LumoAuthAuthenticationException.class);
        assertThatThrownBy(() -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search"))
            .isExactlyInstanceOf(LumoAuthApiException.class)
            .satisfies(e -> assertThat(((LumoAuthApiException) e).statusCode()).isEqualTo(400));
        assertThatThrownBy(() -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "search"))
            .isInstanceOf(LumoAuthRateLimitException.class)
            .satisfies(e -> assertThat(((LumoAuthRateLimitException) e).retryAfter()).contains(Duration.ofSeconds(7)));
    }

    @Test
    void authorizeToolValidatesBeforeSending() {
        String longTool = "t".repeat(81);
        List<Runnable> bad = List.of(
            () -> lumo.mcp().authorizeTool("", "user", "u-1", "search"),
            () -> lumo.mcp().authorizeTool(null, "user", "u-1", "search"),
            () -> lumo.mcp().authorizeTool("mcp/x", "user", "u-1", "search"),
            () -> lumo.mcp().authorizeTool("https://mcp.example.com", "user", "u-1", "search"),
            () -> lumo.mcp().authorizeTool(SERVER, "client", "u-1", "search"),
            () -> lumo.mcp().authorizeTool(SERVER, null, "u-1", "search"),
            () -> lumo.mcp().authorizeTool(SERVER, "user", "", "search"),
            () -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", ""),
            () -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "a/b"),
            () -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "a:b"),
            () -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "a#b"),
            () -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", "*"),
            () -> lumo.mcp().authorizeTool(SERVER, "user", "u-1", longTool));
        for (Runnable r : bad) {
            assertThatThrownBy(r::run).isInstanceOf(LumoAuthValidationException.class);
        }
        server.on("/orgs/acme/api/v1/mcp/servers/" + SERVER + "/tools/authorize", Reply.json(toolBody(true)));
        assertThat(lumo.mcp().authorizeTool(SERVER, "user", "u-1", "t".repeat(80)).allowed()).isTrue();
        assertThat(server.requests()).hasSize(1);
    }

    @Test
    void agentAuthorizeMcpToolAllowsAndDenies() {
        server.queue(AGENT_PATH, Reply.json(agentBody(true)), Reply.json(403, agentBody(false)));
        AgentMcpToolDecision ok = lumo.agents().authorizeMcpTool(SERVER, "search");
        assertThat(ok.allowed()).isTrue();
        assertThat(ok.agentId()).isEqualTo("agt_1");
        assertThat(ok.resource()).isEqualTo(new McpToolDecision.Resource("mcp_tool", SERVER + "/search"));
        FakeServer.Recorded req = server.last();
        assertThat(req.method()).isEqualTo("POST");
        assertThat(req.path()).isEqualTo(AGENT_PATH);
        assertThat(req.header("Authorization")).isEqualTo("Bearer MCP_CC");
        assertThat(req.json()).isEqualTo(Map.of("server_id", SERVER, "tool", "search"));

        AgentMcpToolDecision no = lumo.agents().authorizeMcpTool(SERVER, "search");
        assertThat(no.allowed()).isFalse();
        assertThat(no.agentId()).isEqualTo("agt_1");
    }

    @Test
    void agentAuthorizeMcpToolErrorsAndValidation() {
        server.queue(AGENT_PATH,
            Reply.json(404, Map.of("error", "unknown_server")),
            Reply.json(403, Map.of("error", "agent_required")),
            Reply.json(400, Map.of("error", "invalid_request")));
        assertThatThrownBy(() -> lumo.agents().authorizeMcpTool(SERVER, "search"))
            .isInstanceOf(LumoAuthNotFoundException.class)
            .satisfies(e -> assertThat(((LumoAuthApiException) e).code()).isEqualTo("unknown_server"));
        assertThatThrownBy(() -> lumo.agents().authorizeMcpTool(SERVER, "search"))
            .isInstanceOf(LumoAuthPermissionDeniedException.class)
            .satisfies(e -> assertThat(((LumoAuthApiException) e).code()).isEqualTo("agent_required"));
        assertThatThrownBy(() -> lumo.agents().authorizeMcpTool(SERVER, "search"))
            .isExactlyInstanceOf(LumoAuthApiException.class);
        int before = server.requests().size();
        for (String[] bad : new String[][] {{"", "search"}, {SERVER, ""}, {"a:b", "search"}, {SERVER, "x*"}, {SERVER, "t".repeat(81)}}) {
            assertThatThrownBy(() -> lumo.agents().authorizeMcpTool(bad[0], bad[1])).isInstanceOf(LumoAuthValidationException.class);
        }
        assertThat(server.requests()).hasSize(before);
    }

    @Test
    void lumoAgentUsesItsOwnToken() {
        LumoAgent agent = LumoAgent.builder().baseUrl(server.url()).orgId("acme").clientId("cid").clientSecret("sec").build();
        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "AGT", "expires_in", 3600)));
        server.on(AGENT_PATH, Reply.json(403, agentBody(false)));
        assertThat(agent.authorizeMcpTool(SERVER, "search").allowed()).isFalse();
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer AGT");
    }
}
