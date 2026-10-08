package io.lumoauth.model;

import java.util.Map;

/**
 * Optional arguments shared by every RBAC check.
 *
 * <pre>{@code
 * lumo.permissions().check("document.edit", CheckOptions.forUser("42"));
 * lumo.permissions().check("document.edit", CheckOptions.withContext(Map.of("ip", ip)));
 * }</pre>
 *
 * @param context attributes for ABAC evaluation alongside the RBAC decision
 * @param userId check on behalf of another user (backend credentials only; the
 *               endpoint otherwise defaults to the authenticated principal)
 */
public record CheckOptions(Map<String, Object> context, String userId) {

    public static final CheckOptions NONE = new CheckOptions(null, null);

    public CheckOptions {
        context = Models.map(context);
        userId = Models.blankToNull(userId);
    }

    public static CheckOptions forUser(String userId) {
        return new CheckOptions(null, userId);
    }

    public static CheckOptions withContext(Map<String, Object> context) {
        return new CheckOptions(context, null);
    }

    public CheckOptions context(Map<String, Object> newContext) {
        return new CheckOptions(newContext, userId);
    }

    public CheckOptions user(String newUserId) {
        return new CheckOptions(context, newUserId);
    }
}
