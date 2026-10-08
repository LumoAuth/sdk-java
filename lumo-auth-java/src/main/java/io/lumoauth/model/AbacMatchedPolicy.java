package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** A policy that contributed to an ABAC decision. {@code effect} is "allow" or "deny". */
public record AbacMatchedPolicy(
    @JsonProperty("id") String id,
    @JsonProperty("name") String name,
    @JsonProperty("effect") String effect,
    @JsonProperty("priority") int priority
) {
}
