package io.lumoauth.errors;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * HTTP 403: the principal is authenticated but not allowed. Also raised locally
 * by capability guards such as {@code LumoAgent.requireCapability}, in which case
 * {@link #statusCode()} is 0 because no request was made.
 *
 * <p>When a route needs a user-delegated OAuth scope the credential lacks
 * (for example {@code authz:read} on {@code permissions().list()}), the server
 * answers with the scope body
 * {@code {"error":"forbidden","message":"Insufficient scope: …","status":403,
 * "details":{"required_scopes":["authz:read"],"granted_scopes":[…]}}};
 * {@link #requiredScopes()} lists the scopes it named.
 */
public class LumoAuthPermissionDeniedException extends LumoAuthApiException {

    private final List<String> requiredScopes;

    public LumoAuthPermissionDeniedException(int statusCode, String code, String message, Object body) {
        super(statusCode, code, message, body);
        this.requiredScopes = extractRequiredScopes(body);
    }

    /** A permission denial decided client-side, without a request. */
    public static LumoAuthPermissionDeniedException local(String message) {
        return new LumoAuthPermissionDeniedException(0, ErrorCodes.PERMISSION_DENIED, message, null);
    }

    /**
     * The scopes a 403 scope refusal named in {@code details.required_scopes};
     * empty when the response carried none (a plain permission denial, or a
     * local one). Never null.
     */
    public List<String> requiredScopes() {
        return requiredScopes;
    }

    private static List<String> extractRequiredScopes(Object body) {
        if (!(body instanceof Map<?, ?> map)) {
            return List.of();
        }
        Object details = map.get("details");
        if (!(details instanceof Map<?, ?> detailMap)) {
            return List.of();
        }
        Object raw = detailMap.get("required_scopes");
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<String> scopes = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof String s && !s.isEmpty()) {
                scopes.add(s);
            }
        }
        return Collections.unmodifiableList(scopes);
    }
}
