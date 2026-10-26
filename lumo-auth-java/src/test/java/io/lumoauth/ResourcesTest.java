package io.lumoauth;

import io.lumoauth.errors.LumoAuthApprovalDeniedException;
import io.lumoauth.errors.LumoAuthApprovalTimeoutException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.model.AbacCheck;
import io.lumoauth.model.AbacDecision;
import io.lumoauth.model.ApprovalImpact;
import io.lumoauth.model.ApprovalRequest;
import io.lumoauth.model.ApprovalResult;
import io.lumoauth.model.AttributeType;
import io.lumoauth.model.AuthorizationUrlRequest;
import io.lumoauth.model.CheckOptions;
import io.lumoauth.model.CodeExchangeRequest;
import io.lumoauth.model.ConsentUrlRequest;
import io.lumoauth.model.CreateTaskRequest;
import io.lumoauth.model.EvaluateTaskRequest;
import io.lumoauth.model.JitRequest;
import io.lumoauth.model.PermissionRequest;
import io.lumoauth.model.RegisterAgentRequest;
import io.lumoauth.model.RevokeRequest;
import io.lumoauth.model.TaskResult;
import io.lumoauth.model.TokenExchangeRequest;
import io.lumoauth.resources.AuthResource;
import io.lumoauth.model.UserInfo;
import io.lumoauth.model.WaitOptions;
import io.lumoauth.model.ZanzibarUsersetNode;
import io.lumoauth.resources.DelegationResource;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResourcesTest {

    private final FakeServer server = new FakeServer();
    private final LumoAuth lumo = LumoAuth.builder().baseUrl(server.url()).orgId("acme").apiKey("k").build();

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void permissions() {
        server.on("/api/v1/authz/check", Reply.json(Map.of("allowed", true, "permission", "doc.edit", "user_id", 42)));
        assertThat(lumo.permissions().check("doc.edit", CheckOptions.forUser("42").context(Map.of("ip", "1.1.1.1")))).isTrue();
        assertThat(server.last().json()).containsEntry("permission", "doc.edit")
            .containsEntry("subject", Map.of("type", "user", "id", "42"))
            .doesNotContainKey("user_id")
            .containsEntry("context", Map.of("ip", "1.1.1.1"));
        assertThat(lumo.permissions().checkDetailed("doc.edit", null).userId()).isEqualTo("42");
        assertThat(server.last().json()).containsOnlyKeys("permission");

        server.on("/api/v1/authz/check-bulk", Reply.json(Map.of("results", Map.of("a", true, "b", false))));
        assertThat(lumo.permissions().checkBulk(List.of("a", "b")).allowed("a")).isTrue();
        assertThat(lumo.permissions().checkBulk(List.of("a", "b")).allowed("c")).isFalse();
        lumo.permissions().checkBulk(List.of("a"), CheckOptions.forAgent("agt_1"));
        assertThat(server.last().json()).containsEntry("subject", Map.of("type", "agent", "id", "agt_1"))
            .doesNotContainKey("user_id");
        server.on("/api/v1/authz/check-any", Reply.json(Map.of("allowed", true, "permissions", List.of("a"))));
        server.on("/api/v1/authz/check-all", Reply.json(Map.of("allowed", false)));
        assertThat(lumo.permissions().checkAny(List.of("a", "b"))).isTrue();
        assertThat(lumo.permissions().checkAll(List.of("a", "b"))).isFalse();
        lumo.permissions().checkAny(List.of("a"), CheckOptions.forUser("u-9"));
        assertThat(server.last().json()).containsEntry("subject", Map.of("type", "user", "id", "u-9"));
        lumo.permissions().checkAll(List.of("a"), CheckOptions.forUser("u-9"));
        assertThat(server.last().json()).containsEntry("subject", Map.of("type", "user", "id", "u-9"))
            .doesNotContainKey("user_id");
        assertThatThrownBy(() -> new CheckOptions(null, "u", "agt_1")).isInstanceOf(IllegalArgumentException.class);
        assertThat(CheckOptions.forUser("u").agent("agt_1").userId()).isNull();
        server.on("/api/v1/authz/permissions", Reply.json(Map.of("permissions", List.of(Map.of("slug", "a"), Map.of("slug", "b", "source", "role")), "count", 2)));
        assertThat(lumo.permissions().listSlugs()).containsExactly("a", "b");
        assertThat(lumo.permissions().list().permissions().get(1).source()).isEqualTo("role");

        assertThatThrownBy(() -> lumo.permissions().check("")).isInstanceOf(LumoAuthValidationException.class);
        assertThatThrownBy(() -> lumo.permissions().checkAll(List.of())).isInstanceOf(LumoAuthValidationException.class);
    }

    @Test
    void zanzibar() {
        server.on("/api/v1/authz/zanzibar/check", Reply.json(Map.of("allowed", true, "object", "document:1")));
        assertThat(lumo.zanzibar().isViewer("document:1", "user:bob")).isTrue();
        assertThat(server.last().json()).containsEntry("relation", "viewer").containsEntry("subject", "user:bob");
        assertThat(lumo.zanzibar().checkDetailed("document:1", "owner", "group:eng#member").object()).isEqualTo("document:1");
        assertThatThrownBy(() -> lumo.zanzibar().check("document", "viewer", "user:bob")).hasMessageContaining("namespace:id");
        assertThatThrownBy(() -> lumo.zanzibar().check("document:1", "", "user:bob")).hasMessageContaining("relation");
        assertThatThrownBy(() -> lumo.zanzibar().check("document:1", "viewer", "bob")).hasMessageContaining("subject");

        server.on("/api/v1/authz/zanzibar/expand", Reply.json(Map.of("tree", Map.of("type", "union", "children",
            List.of(Map.of("type", "leaf", "subjects", List.of("user:a")), Map.of("type", "leaf", "subjects", List.of("user:b", "user:a")))))));
        ZanzibarUsersetNode tree = lumo.zanzibar().expand("document:1", "viewer");
        assertThat(tree.type()).isEqualTo("union");
        assertThat(tree.allSubjects()).containsExactly("user:a", "user:b");
        server.on("/api/v1/authz/zanzibar/expand", Reply.json(Map.of()));
        assertThatThrownBy(() -> lumo.zanzibar().expand("document:1", "viewer")).hasMessageContaining("tree");
    }

    @Test
    void abac() {
        server.on("/orgs/acme/api/v1/abac/check", Reply.json(Map.of("allowed", false, "reason", "default deny",
            "matchedPolicies", List.of(Map.of("id", "p1", "name", "N", "effect", "deny", "priority", 5)), "resourceType", "document")));
        AbacDecision decision = lumo.abac().check(AbacCheck.of("document", "read", "doc-1").context(Map.of("env", Map.of("ip", "1"))));
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.matchedPolicies().get(0).effect()).isEqualTo("deny");
        assertThat(decision.raw()).containsEntry("resourceType", "document");
        assertThat(server.last().json()).containsEntry("resourceType", "document").containsEntry("resourceId", "doc-1")
            .containsEntry("environment", Map.of("env", Map.of("ip", "1"))).doesNotContainKey("context");
        assertThat(lumo.abac().isAllowed(AbacCheck.of("document", "read"))).isFalse();
        assertThat(server.last().json()).doesNotContainKeys("resourceId", "context", "environment");
        assertThatThrownBy(() -> lumo.abac().check(AbacCheck.of("", "read"))).hasMessageContaining("resourceType");

        server.on("/orgs/acme/api/v1/abac/check-bulk", Reply.json(Map.of("results", List.of(Map.of("allowed", true), Map.of("allowed", false)))));
        List<AbacDecision> bulk = lumo.abac().checkBulk(List.of(AbacCheck.of("d", "read"), AbacCheck.of("d", "write")));
        assertThat(bulk).extracting(AbacDecision::allowed).containsExactly(true, false);
        assertThat(server.last().json()).containsKey("checks").doesNotContainKeys("requests", "environment");
        Map<String, Object> env = Map.of("pep", Map.of("ip", "10.0.0.8"));
        lumo.abac().checkBulk(List.of(AbacCheck.of("d", "read").context(env), AbacCheck.of("d", "write").resourceId("x").context(env)));
        assertThat(server.last().json()).containsEntry("environment", env)
            .containsEntry("checks", List.of(Map.of("resourceType", "d", "action", "read"),
                Map.of("resourceType", "d", "action", "write", "resourceId", "x")));
        lumo.abac().checkBulk(List.of(AbacCheck.of("d", "read").context(Map.of("ignored", 1))), env);
        assertThat(server.last().json()).containsEntry("environment", env)
            .containsEntry("checks", List.of(Map.of("resourceType", "d", "action", "read")));
        assertThatThrownBy(() -> lumo.abac().checkBulk(List.of(AbacCheck.of("d", "read").context(env), AbacCheck.of("d", "write"))))
            .isInstanceOf(io.lumoauth.errors.LumoAuthValidationException.class)
            .hasMessageContaining("one environment to every check");
        assertThatThrownBy(() -> lumo.abac().checkBulk(List.of())).hasMessageContaining("at least one");
        assertThatThrownBy(() -> lumo.abac().checkBulk(List.of(AbacCheck.of("d", "r"), AbacCheck.of("", "r")))).hasMessageContaining("check 1");

        server.on("/orgs/acme/api/v1/abac/my-attributes", Reply.json(Map.of("department", "eng")));
        assertThat(lumo.abac().myAttributes()).containsEntry("department", "eng");
        server.on("/orgs/acme/api/v1/abac/users/u1/attributes/dept", Reply.empty(204));
        lumo.abac().setUserAttribute("u1", "dept", "eng");
        assertThat(server.last().method()).isEqualTo("PUT");
        assertThat(server.last().json()).containsEntry("value", "eng");
        server.on("/orgs/acme/api/v1/abac/resources/document/d1/attributes", Reply.json(Map.of("owner", "u1")));
        assertThat(lumo.abac().resourceAttributes("document", "d1")).containsEntry("owner", "u1");
        server.on("/orgs/acme/api/v1/abac/resources/document/d1/attributes/level", Reply.empty(204));
        lumo.abac().setResourceAttribute("document", "d1", "level", 3);
        assertThat(server.last().json()).containsEntry("value", 3);

        server.on("/orgs/acme/api/v1/abac/attribute-definitions", Reply.json(Map.of("data", List.of(Map.of("id", "1", "slug", "dept", "attributeType", "user", "isActive", true)))));
        assertThat(lumo.abac().attributeDefinitions(AttributeType.USER).get(0).active()).isTrue();
        assertThat(server.last().query()).isEqualTo("type=user");
        server.on("/orgs/acme/api/v1/abac/attribute-definitions", Reply.json(List.of(Map.of("id", "2", "slug", "x"))));
        assertThat(lumo.abac().attributeDefinitions()).hasSize(1);
    }

    @Test
    void auth() {
        String url = lumo.auth().authorizationUrl(AuthorizationUrlRequest.builder("cid", "https://app/cb")
            .state("s").codeChallenge("ch").prompt("consent").accessType("offline").extra("ui_locales", "fr").build());
        assertThat(url).startsWith(server.url() + "/orgs/acme/api/v1/oauth/authorize?")
            .contains("response_type=code").contains("client_id=cid").contains("redirect_uri=https%3A%2F%2Fapp%2Fcb")
            .contains("scope=openid+profile+email").contains("code_challenge=ch").contains("code_challenge_method=S256")
            .contains("prompt=consent").contains("access_type=offline").contains("ui_locales=fr");
        assertThatThrownBy(() -> lumo.auth().authorizationUrl(AuthorizationUrlRequest.builder("", "x").build())).hasMessageContaining("clientId");

        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "A", "refresh_token", "R", "expires_in", 3600, "scope", "a b")));
        assertThat(lumo.auth().exchangeCode(CodeExchangeRequest.of("c", "https://app/cb", "cid").clientSecret("sec").codeVerifier("v")).scopes()).containsExactly("a", "b");
        assertThat(server.last().form()).containsEntry("grant_type", "authorization_code").containsEntry("code_verifier", "v").containsEntry("client_secret", "sec");
        assertThat(lumo.auth().refreshToken(io.lumoauth.model.RefreshTokenRequest.of("R", "cid", "sec").scopes(List.of("a"))).accessToken()).isEqualTo("A");
        assertThat(server.last().form()).containsEntry("grant_type", "refresh_token").containsEntry("scope", "a");
        assertThat(lumo.auth().tokenExchange(TokenExchangeRequest.of("S").actorToken("ACT").audience("urn:mcp:x").scopes(List.of("r"))).accessToken()).isEqualTo("A");
        assertThat(server.last().form()).containsEntry("subject_token", "S").containsEntry("actor_token", "ACT")
            .containsEntry("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
            .containsEntry("actor_token_type", "urn:ietf:params:oauth:token-type:access_token").containsEntry("audience", "urn:mcp:x")
            .doesNotContainKey("resource");
        // The RFC 8707 resource indicator binds the delegated token's aud.
        lumo.delegation().exchangeForResource("S", "ACT", "https://api.example.com", List.of("r"));
        assertThat(server.last().form()).containsEntry("resource", "https://api.example.com").containsEntry("scope", "r");
        // An ID token (or workload JWT) is declared as such; the actor default stays access_token.
        lumo.auth().tokenExchange(TokenExchangeRequest.of("ID").subjectTokenType(AuthResource.TOKEN_TYPE_ID_TOKEN).actorToken("ACT"));
        assertThat(server.last().form()).containsEntry("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
            .containsEntry("actor_token_type", "urn:ietf:params:oauth:token-type:access_token");
        assertThatThrownBy(() -> lumo.auth().clientCredentials("", "s")).isInstanceOf(LumoAuthValidationException.class);

        server.on("/orgs/acme/api/v1/oauth/revoke", Reply.empty(200));
        lumo.auth().revoke(RevokeRequest.refreshToken("R", "cid", "sec"));
        assertThat(server.last().form()).containsEntry("token_type_hint", "refresh_token").containsEntry("client_id", "cid");
        assertThat(server.last().header("X-API-Key")).isNull();

        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "u1", "email", "a@b", "roles", List.of("admin"),
            "agent_id", "ag", "capabilities", List.of("tool:x"), "budget_policy", Map.of("max_tokens_per_day", 10, "tokens_used_today", 10), "custom", 1)));
        UserInfo info = lumo.auth().userinfo();
        assertThat(info.isAgent()).isTrue();
        assertThat(info.roles()).containsExactly("admin");
        assertThat(info.budgetPolicy().exhausted()).isTrue();
        assertThat(info.claim("custom")).contains(1);
        assertThat(server.last().header("X-API-Key")).isEqualTo("k");
    }

    @Test
    void agents() {
        server.on("/orgs/acme/api/v1/agents/ask", Reply.json(Map.of("allowed", false, "reason", "no", "audit_id", "au")));
        assertThat(lumo.agents().ask("send_email", Map.of("to", "x")).reason()).isEqualTo("no");
        assertThat(server.last().json()).containsEntry("action", "send_email").containsEntry("context", Map.of("to", "x"));
        assertThat(lumo.agents().isAllowed("send_email")).isFalse();
        assertThat(server.last().json()).doesNotContainKey("context");
        assertThatThrownBy(() -> lumo.agents().ask("")).isInstanceOf(LumoAuthValidationException.class);

        server.on("/orgs/acme/api/v1/agents/me", Reply.json(Map.of("identity", Map.of("id", 7, "name", "A"), "capabilities", List.of("c"))));
        assertThat(lumo.agents().me().id()).contains("7");
        server.on("/orgs/acme/api/v1/agents/register", Reply.json(201, Map.of("agent_id", "ag", "success", true)));
        assertThat(lumo.agents().register(RegisterAgentRequest.builder("A", "cid").capabilities(List.of("c")).jwksUri("https://j").build()).agentId()).isEqualTo("ag");
        assertThat(server.last().json()).containsEntry("client_id", "cid").containsEntry("jwks_uri", "https://j").containsEntry("capabilities", List.of("c"));
        assertThatThrownBy(() -> lumo.agents().register(RegisterAgentRequest.builder("", "cid").build())).hasMessageContaining("name");

        server.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "u1", "capabilities", List.of("tool:x"))));
        assertThat(lumo.agents().capabilities()).containsExactly("tool:x");
        assertThat(lumo.agents().budget().exhausted()).isFalse();
    }

    @Test
    void approvals() {
        String create = "/orgs/acme/api/v1/agents/me/approvals";
        String status = "/orgs/acme/api/v1/agents/me/approvals/tok/status";
        WaitOptions fast = WaitOptions.of(Duration.ofMillis(10), Duration.ofSeconds(5));
        ApprovalRequest request = ApprovalRequest.builder("t1", "Wire money", "ada@acme.com").impact(ApprovalImpact.HIGH).meta(Map.of("amount", 4500)).build();

        server.on(create, Reply.json(201, Map.of("approval_token", "tok", "status", "pending", "impact", "high")));
        server.queue(status, Reply.json(Map.of("status", "pending")), Reply.json(Map.of("status", "approved", "approved_by", Map.of("email", "ada@acme.com"))));
        ApprovalResult approved = lumo.approvals().require(request, fast);
        assertThat(approved.approved()).isTrue();
        assertThat(approved.token()).isEqualTo("tok");
        assertThat(approved.approvedBy().email()).isEqualTo("ada@acme.com");
        assertThat(server.requests().get(0).json()).containsEntry("task_id", "t1").containsEntry("impact", "high")
            .containsEntry("on_behalf_of", "ada@acme.com").containsEntry("meta", Map.of("amount", 4500));
        assertThat(server.requests()).hasSize(3);

        server.reset();
        server.on(status, Reply.json(Map.of("status", "denied", "approval_token", "tok")));
        assertThatThrownBy(() -> lumo.approvals().require(request, fast))
            .isInstanceOf(LumoAuthApprovalDeniedException.class)
            .satisfies(e -> assertThat(((LumoAuthApprovalDeniedException) e).approval().denied()).isTrue());

        server.on(status, Reply.json(Map.of("status", "pending")));
        assertThatThrownBy(() -> lumo.approvals().require(request, WaitOptions.of(Duration.ofMillis(5), Duration.ofMillis(30))))
            .isInstanceOf(LumoAuthApprovalTimeoutException.class)
            .satisfies(e -> assertThat(((LumoAuthApprovalTimeoutException) e).approval().pending()).isTrue());

        server.on(status, Reply.json(Map.of("status", "expired")));
        assertThatThrownBy(() -> lumo.approvals().require(request, fast)).isInstanceOf(LumoAuthApprovalTimeoutException.class);

        assertThatThrownBy(() -> lumo.approvals().create(ApprovalRequest.builder("t", "", "u").build())).hasMessageContaining("reason");
        assertThat(ApprovalRequest.builder("t", "r", "u").build().impact()).isEqualTo(ApprovalImpact.MEDIUM);
        server.on(create, Reply.json(202, Map.of("status", "email_fallback_sent")));
        assertThatThrownBy(() -> lumo.approvals().create(request)).hasMessageContaining("approval_token");
    }

    @Test
    void jit() {
        server.on("/orgs/acme/api/v1/jit/task", Reply.json(201, Map.of("task_id", "task-1", "caep_session_id", "caep", "expires_at", "2026-10-08T12:00:00+00:00")));
        var task = lumo.jit().createTask(CreateTaskRequest.named("Analyse").type("analysis").onBehalfOf("ada@acme.com"));
        assertThat(task.taskId()).isEqualTo("task-1");
        assertThat(task.expiresAtInstant()).isPresent();
        assertThat(server.last().json()).containsEntry("name", "Analyse").containsEntry("type", "analysis").containsEntry("on_behalf_of", "ada@acme.com");

        server.on("/orgs/acme/api/v1/jit/request", Reply.json(201, Map.of("request_id", "r1", "status", "approved", "granted_ttl", 300)));
        JitRequest result = lumo.jit().request(PermissionRequest.of("task-1", Map.of("type", "file_access")).justification("j").ttl(5000));
        assertThat(result.approved()).isTrue();
        assertThat(result.grantedTtl()).isEqualTo(300);
        assertThat(server.last().json()).containsEntry("requested_ttl", PermissionRequest.MAX_TTL).containsEntry("justification", "j");
        assertThatThrownBy(() -> lumo.jit().request(PermissionRequest.of("task-1", Map.of()))).hasMessageContaining("RFC 9396");

        server.on("/orgs/acme/api/v1/jit/request/r1/status", Reply.json(Map.of("request_id", "r1", "status", "pending")));
        assertThat(lumo.jit().status("r1").pending()).isTrue();
        server.on("/orgs/acme/api/v1/jit/request/r1/token", Reply.json(Map.of("access_token", "JIT", "expires_in", 300)));
        assertThat(lumo.jit().token("r1").accessToken()).isEqualTo("JIT");
        server.on("/orgs/acme/api/v1/jit/pending", Reply.json(Map.of("requests", List.of(Map.of("request_id", "r2", "status", "pending")))));
        assertThat(lumo.jit().pending()).extracting(JitRequest::requestId).containsExactly("r2");
        server.on("/orgs/acme/api/v1/jit/pending", Reply.json(List.of()));
        assertThat(lumo.jit().pending()).isEmpty();
        server.on("/orgs/acme/api/v1/jit/task/task-1/evaluate", Reply.json(Map.of("ok", true)));
        assertThat(lumo.jit().evaluateTask("task-1", EvaluateTaskRequest.of(TaskResult.FAILED, "boom"))).containsEntry("ok", true);
        assertThat(server.last().json()).containsEntry("result", "failed").containsEntry("notes", "boom");
        server.on("/orgs/acme/api/v1/jit/task/task-1/complete", Reply.empty(204));
        lumo.jit().completeTask("task-1");
        assertThatThrownBy(() -> lumo.jit().completeTask("")).isInstanceOf(LumoAuthValidationException.class);
    }

    @Test
    void delegationAndMcp() {
        String url = lumo.delegation().consentUrl(ConsentUrlRequest.of("cid", "https://cb").state("s"));
        assertThat(url).contains("scope=read%3Adocuments").contains("prompt=consent").contains("access_type=offline").contains("state=s");
        server.on("/orgs/acme/api/v1/oauth/token", Reply.json(Map.of("access_token", "D")));
        assertThat(lumo.delegation().exchange("SUB", "ACT", "r").accessToken()).isEqualTo("D");
        assertThat(server.last().form()).containsEntry("scope", "r").containsEntry("grant_type", DelegationResource.class.getName().isEmpty() ? "" : "urn:ietf:params:oauth:grant-type:token-exchange");
        assertThatThrownBy(() -> lumo.delegation().exchange("", "ACT")).hasMessageContaining("subject token");

        String jwt = "x." + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            "{\"sub\":\"user:ada\",\"act\":{\"sub\":\"agent:a\",\"act\":{\"sub\":\"agent:b\"}}}".getBytes()) + ".sig";
        assertThat(DelegationResource.parseActorChain(jwt)).containsExactly("agent:a", "agent:b");
        assertThat(DelegationResource.tokenSubject(jwt)).contains("user:ada");
        assertThatThrownBy(() -> DelegationResource.tokenSubject("nope")).isInstanceOf(LumoAuthValidationException.class);

        assertThat(lumo.mcp().token("urn:mcp:fin", "SUBJ")).isEqualTo("D");
        assertThat(server.last().form()).containsEntry("audience", "urn:mcp:fin").containsEntry("subject_token", "SUBJ").doesNotContainKey("actor_token");
        assertThatThrownBy(() -> lumo.mcp().token("urn:mcp:fin")).isInstanceOf(LumoAuthConfigException.class).hasMessageContaining("subject token");
        LumoAuth bearer = LumoAuth.builder().baseUrl(server.url()).orgId("acme").apiKey(null).accessToken("ME").build();
        assertThat(bearer.mcp().tokenDetailed("urn:mcp:fin", null).accessToken()).isEqualTo("D");
        assertThat(server.last().form()).containsEntry("subject_token", "ME");
        assertThatThrownBy(() -> lumo.mcp().token("")).isInstanceOf(LumoAuthValidationException.class);
    }
}
