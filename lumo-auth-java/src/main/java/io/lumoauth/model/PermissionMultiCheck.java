package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/** The result of a check-any / check-all call. */
public record PermissionMultiCheck(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("permissions") List<String> permissions,
    @JsonProperty("user_id") String userId,
    @JsonProperty("context") Map<String, Object> context
) {
    public PermissionMultiCheck {
        permissions = Models.list(permissions);
        context = Models.map(context);
    }
}
