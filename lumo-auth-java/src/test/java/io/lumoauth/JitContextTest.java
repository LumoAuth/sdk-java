package io.lumoauth;

import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.model.CreateTaskRequest;
import io.lumoauth.model.JitRequest;
import io.lumoauth.model.WaitOptions;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JitContextTest {

    private final FakeServer server = new FakeServer();
    private final TokenSource source = new TokenSource() {
        public String baseUrl() { return server.url(); }
        public String orgId() { return "acme"; }
        public String accessToken() { return "AGENT"; }
    };

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void lifecycleWithTryWithResources() {
        server.on("/orgs/acme/api/v1/jit/task", Reply.json(201, Map.of("task_id", "t1", "caep_session_id", "c1")));
        server.on("/orgs/acme/api/v1/jit/request", Reply.json(201, Map.of("request_id", "r1", "status", "pending")));
        server.queue("/orgs/acme/api/v1/jit/request/r1/status", Reply.json(Map.of("request_id", "r1", "status", "pending")),
            Reply.json(Map.of("request_id", "r1", "status", "approved")));
        server.on("/orgs/acme/api/v1/jit/request/r1/token", Reply.json(Map.of("access_token", "JIT")));
        server.on("/orgs/acme/api/v1/jit/task/t1/complete", Reply.empty(204));
        server.on("/data", Reply.json(Map.of("ok", true)));

        try (JitContext jit = new JitContext(source)) {
            jit.createTask(CreateTaskRequest.named("Analyse"));
            assertThat(jit.taskId()).contains("t1");
            assertThat(jit.caepSessionId()).contains("c1");
            JitRequest result = jit.requestPermission(Map.of("type", "file_access"),
                JitContext.RequestOptions.justification("because").polling(WaitOptions.of(Duration.ofMillis(5), Duration.ofSeconds(5))));
            assertThat(result.approved()).isTrue();
            assertThat(server.requests().get(1).json()).containsEntry("task_id", "t1").containsEntry("justification", "because");
            assertThat(server.requests().get(1).header("Authorization")).isEqualTo("Bearer AGENT");
            String token = jit.token(result.requestId());
            HttpResponse<byte[]> response = jit.call(token, "GET", server.url() + "/data", null);
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(server.last().header("Authorization")).isEqualTo("Bearer JIT");
        }
        assertThat(server.last().path()).isEqualTo("/orgs/acme/api/v1/jit/task/t1/complete");
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer AGENT");
    }

    @Test
    void noWaitReturnsPendingAndRequiresATask() {
        JitContext jit = new JitContext(source);
        assertThatThrownBy(() -> jit.requestPermission(Map.of("type", "x"))).isInstanceOf(LumoAuthConfigException.class).hasMessageContaining("createTask");
        server.on("/orgs/acme/api/v1/jit/request", Reply.json(201, Map.of("request_id", "r1", "status", "pending")));
        JitRequest pending = jit.requestPermission(Map.of("type", "x"), JitContext.RequestOptions.DEFAULTS.noWait().taskId("explicit"));
        assertThat(pending.pending()).isTrue();
        assertThat(server.only().json()).containsEntry("task_id", "explicit");
        jit.close(); // no task: no request
        assertThat(server.requests()).hasSize(1);
    }

    @Test
    void delegatedTokenIsUsedForJitCalls() {
        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "DELEGATED")));
        server.on("/orgs/acme/api/v1/jit/task", Reply.json(201, Map.of("task_id", "t1")));
        JitContext jit = new JitContext(source);
        jit.delegateOnBehalfOf("USER");
        assertThat(server.last().form()).containsEntry("subject_token", "USER").containsEntry("actor_token", "AGENT");
        jit.createTask();
        assertThat(server.last().header("Authorization")).isEqualTo("Bearer DELEGATED");
        assertThat(new JitContext(source, "PRESET")).isNotNull();
    }

    @Test
    void escalatesOnInsufficientAuthorizationDetails() {
        String details = Base64.getEncoder().encodeToString("{\"type\":\"file_access\",\"actions\":[\"read\"]}".getBytes());
        server.on("/resource", req -> "Bearer JIT".equals(req.header("Authorization"))
            ? Reply.json(Map.of("ok", true))
            : Reply.json(403, Map.of("error", "insufficient")).header("Insufficient-Authorization-Details", details));
        server.on("/orgs/acme/api/v1/jit/task", Reply.json(201, Map.of("task_id", "t1")));
        server.on("/orgs/acme/api/v1/jit/request", Reply.json(201, Map.of("request_id", "r1", "status", "approved")));
        server.on("/orgs/acme/api/v1/jit/request/r1/token", Reply.json(Map.of("access_token", "JIT")));

        JitContext jit = new JitContext(source);
        jit.createTask();
        HttpResponse<byte[]> response = jit.callWithEscalation("GET", server.url() + "/resource", null);
        assertThat(response.statusCode()).isEqualTo(200);
        FakeServer.Recorded permission = server.requests().stream().filter(r -> r.path().endsWith("/jit/request")).findFirst().orElseThrow();
        assertThat(permission.json()).containsEntry("authorization_details", Map.of("type", "file_access", "actions", List.of("read")))
            .containsEntry("justification", "Required for user request");

        // Escalation refused: the original 403 stands.
        server.on("/orgs/acme/api/v1/jit/request", Reply.json(201, Map.of("request_id", "r2", "status", "denied")));
        assertThat(jit.callWithEscalation("GET", server.url() + "/resource", null).statusCode()).isEqualTo(403);
        // Unusable hint: the original 403 stands.
        server.on("/plain403", Reply.json(403, Map.of()).header("Insufficient-Authorization-Details", "%%%"));
        assertThat(jit.callWithEscalation("GET", server.url() + "/plain403", null).statusCode()).isEqualTo(403);
    }
}
