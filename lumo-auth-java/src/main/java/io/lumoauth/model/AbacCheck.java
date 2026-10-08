package io.lumoauth.model;

import io.lumoauth.errors.LumoAuthValidationException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One ABAC evaluation.
 *
 * <pre>{@code
 * AbacCheck.of("document", "read").resourceId("doc-123")
 *     .context(Map.of("environment", Map.of("ip", "10.0.0.1")));
 * }</pre>
 *
 * @param resourceType the kind of thing being accessed ("document"). Required.
 * @param action       the operation ("read", "delete"). Required.
 * @param resourceId   the specific instance, when there is one.
 * @param context      resource and environment attributes for the evaluation.
 */
public record AbacCheck(String resourceType, String action, String resourceId, Map<String, Object> context) {

    public AbacCheck {
        context = Models.map(context);
        resourceId = Models.blankToNull(resourceId);
    }

    public static AbacCheck of(String resourceType, String action) {
        return new AbacCheck(resourceType, action, null, null);
    }

    public static AbacCheck of(String resourceType, String action, String resourceId) {
        return new AbacCheck(resourceType, action, resourceId, null);
    }

    public AbacCheck resourceId(String newResourceId) {
        return new AbacCheck(resourceType, action, newResourceId, context);
    }

    public AbacCheck context(Map<String, Object> newContext) {
        return new AbacCheck(resourceType, action, resourceId, newContext);
    }

    /** The wire body (camelCase keys), validating the required fields. */
    public Map<String, Object> toBody() {
        if (resourceType == null || resourceType.isBlank()) {
            throw new LumoAuthValidationException("resourceType is required for an ABAC check");
        }
        if (action == null || action.isBlank()) {
            throw new LumoAuthValidationException("action is required for an ABAC check");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resourceType", resourceType);
        body.put("action", action);
        if (resourceId != null) {
            body.put("resourceId", resourceId);
        }
        if (!context.isEmpty()) {
            body.put("context", context);
        }
        return body;
    }
}
