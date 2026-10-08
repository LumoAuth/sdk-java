package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** The human who responded to an approval request. */
public record Approver(
    @JsonProperty("user_id") String userId,
    @JsonProperty("email") String email
) {
}
