package io.lumoauth.resources;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.internal.Json;
import io.lumoauth.model.CreateTaskRequest;
import io.lumoauth.model.EvaluateTaskRequest;
import io.lumoauth.model.JitRequest;
import io.lumoauth.model.JitTask;
import io.lumoauth.model.PermissionRequest;
import io.lumoauth.model.TokenResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The Just-in-Time permission endpoints: ephemeral tasks, RFC 9396
 * permission requests, and short-lived scoped tokens. For the full lifecycle
 * with automatic cleanup use {@link io.lumoauth.JitContext}, which wraps this.
 */
public final class JitResource {

    private final HttpTransport http;

    public JitResource(HttpTransport http) {
        this.http = http;
    }

    /** Opens an ephemeral task whose JIT tokens are revoked together when it completes. */
    public JitTask createTask(CreateTaskRequest params) {
        CreateTaskRequest request = params == null ? CreateTaskRequest.EMPTY : params;
        JitTask task = http.call(Routes.JIT_CREATE_TASK, null, ApiRequest.json(request.toBody()), JitTask.class);
        if (task == null || task.taskId() == null || task.taskId().isEmpty()) {
            throw new LumoAuthValidationException("the server did not return a task_id");
        }
        return task;
    }

    /** Closes a task and revokes every JIT token issued under it. */
    public void completeTask(String taskId) {
        requireTaskId(taskId);
        http.callNode(Routes.JIT_COMPLETE_TASK, Map.of("taskId", taskId), null);
    }

    /** Closes a task with an outcome and audit notes. */
    public Map<String, Object> evaluateTask(String taskId, EvaluateTaskRequest params) {
        requireTaskId(taskId);
        EvaluateTaskRequest request = params == null ? EvaluateTaskRequest.completed() : params;
        JsonNode node = http.callNode(Routes.JIT_EVALUATE_TASK, Map.of("taskId", taskId), ApiRequest.json(request.toBody()));
        return Json.toMap(node);
    }

    /**
     * Asks for a Just-in-Time permission. Low-risk requests come back approved;
     * higher-risk ones enter human-in-the-loop review as pending.
     */
    public JitRequest request(PermissionRequest params) {
        return http.call(Routes.JIT_REQUEST, null, ApiRequest.json(params.toBody()), JitRequest.class);
    }

    /** The current state of a permission request. */
    public JitRequest status(String requestId) {
        requireRequestId(requestId);
        return http.call(Routes.JIT_REQUEST_STATUS, Map.of("requestId", requestId), null, JitRequest.class);
    }

    /** Exchanges an approved request for a short-lived, narrowly scoped JIT access token. */
    public TokenResponse token(String requestId) {
        requireRequestId(requestId);
        TokenResponse token = http.call(Routes.JIT_TOKEN, Map.of("requestId", requestId), null, TokenResponse.class);
        if (token == null || token.accessToken() == null || token.accessToken().isEmpty()) {
            throw new LumoAuthValidationException("the JIT token endpoint returned no access_token");
        }
        return token;
    }

    /**
     * The permission requests awaiting human approval. This is a reviewer call: it takes a browser
     * session or a user access token with the {@code jit:approve} scope, never an agent credential.
     */
    public List<JitRequest> pending() {
        // The endpoint returns either a bare array or an envelope with `requests`.
        JsonNode node = http.callNode(Routes.JIT_PENDING, null, null);
        if (node == null) {
            return List.of();
        }
        JsonNode array = node.isArray() ? node : node.get("requests");
        if (array == null || !array.isArray()) {
            throw new LumoAuthValidationException("could not decode the pending requests response");
        }
        List<JitRequest> out = new ArrayList<>();
        for (JsonNode item : array) {
            out.add(Json.convert(item, JitRequest.class, "jit.pending"));
        }
        return List.copyOf(out);
    }

    private static void requireTaskId(String taskId) {
        if (taskId == null || taskId.isBlank()) {
            throw new LumoAuthValidationException("a task ID is required");
        }
    }

    private static void requireRequestId(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new LumoAuthValidationException("a request ID is required");
        }
    }
}
