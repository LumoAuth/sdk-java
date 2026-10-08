package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/** The result of a bulk permission check: one decision per requested slug. */
public record PermissionBulkCheck(
    @JsonProperty("results") Map<String, Boolean> results,
    @JsonProperty("user_id") String userId,
    @JsonProperty("context") Map<String, Object> context
) {
    public PermissionBulkCheck {
        results = Models.map(results);
        context = Models.map(context);
    }

    /** The decision for one slug; false when the server did not return it. */
    public boolean allowed(String permission) {
        return Boolean.TRUE.equals(results.get(permission));
    }
}
