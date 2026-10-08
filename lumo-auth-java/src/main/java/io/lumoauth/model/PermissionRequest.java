package io.lumoauth.model;

import io.lumoauth.errors.LumoAuthValidationException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An RFC 9396 Just-in-Time permission request.
 *
 * <pre>{@code
 * PermissionRequest.of(taskId, Map.of(
 *         "type", "file_access", "actions", List.of("read"), "identifier", "report.pdf"))
 *     .justification("The user asked for a Q4 summary")
 *     .ttl(300);
 * }</pre>
 *
 * @param taskId               the task the permission attaches to. Required.
 * @param authorizationDetails the RFC 9396 structured object. Required.
 * @param justification        the human-readable reason shown to an approver.
 * @param ttl                  the requested token lifetime in seconds, capped at {@link #MAX_TTL}; 0 means {@link #DEFAULT_TTL}.
 */
public record PermissionRequest(String taskId, Map<String, Object> authorizationDetails, String justification, int ttl) {

    /** The longest lifetime the server will grant a JIT token, in seconds (15 min). */
    public static final int MAX_TTL = 900;
    /** The requested lifetime when a call does not specify one, in seconds. */
    public static final int DEFAULT_TTL = 300;

    public PermissionRequest {
        authorizationDetails = Models.map(authorizationDetails);
    }

    public static PermissionRequest of(String taskId, Map<String, Object> authorizationDetails) {
        return new PermissionRequest(taskId, authorizationDetails, null, 0);
    }

    public PermissionRequest justification(String value) {
        return new PermissionRequest(taskId, authorizationDetails, value, ttl);
    }

    public PermissionRequest ttl(int seconds) {
        return new PermissionRequest(taskId, authorizationDetails, justification, seconds);
    }

    public PermissionRequest taskId(String value) {
        return new PermissionRequest(value, authorizationDetails, justification, ttl);
    }

    /** The effective TTL: the default when unset, capped at the server maximum. */
    public int effectiveTtl() {
        int value = ttl <= 0 ? DEFAULT_TTL : ttl;
        return Math.min(value, MAX_TTL);
    }

    public Map<String, Object> toBody() {
        if (taskId == null || taskId.isBlank()) {
            throw new LumoAuthValidationException("taskId is required - create a task first");
        }
        if (authorizationDetails.isEmpty()) {
            throw new LumoAuthValidationException("authorizationDetails is required (RFC 9396)");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("task_id", taskId);
        body.put("authorization_details", authorizationDetails);
        body.put("requested_ttl", effectiveTtl());
        if (justification != null && !justification.isBlank()) {
            body.put("justification", justification);
        }
        return body;
    }
}
