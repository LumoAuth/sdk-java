package io.lumoauth.model;

import io.lumoauth.errors.LumoAuthValidationException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One ABAC evaluation.
 *
 * <pre>{@code
 * AbacCheck.of("document", "read").resourceId("doc-123")
 *     .context(Map.of("pep", Map.of("ip", endUserIp)));
 * }</pre>
 *
 * @param resourceType the kind of thing being accessed ("document"). Required.
 * @param action       the operation ("read", "delete"). Required.
 * @param resourceId   the specific instance, when there is one.
 * @param context      environment attributes for the evaluation, sent to the server as
 *                     {@code environment}. The server sets {@code ip}, {@code userAgent},
 *                     {@code requestMethod} and {@code requestPath} itself; values that you pass
 *                     under those names are kept under {@code pep}.
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
            // The check endpoint reads the attributes from `environment` only.
            body.put("environment", context);
        }
        return body;
    }

    /** The wire entry for one item of a bulk check: no environment (the bulk call sends one shared). */
    public Map<String, Object> toBulkEntry() {
        Map<String, Object> body = toBody();
        body.remove("environment");
        return body;
    }
}
