package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/** The result of a single permission check. */
public record PermissionCheck(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("permission") String permission,
    @JsonProperty("user_id") String userId,
    @JsonProperty("context") Map<String, Object> context
) {
    public PermissionCheck {
        context = Models.map(context);
    }
}
