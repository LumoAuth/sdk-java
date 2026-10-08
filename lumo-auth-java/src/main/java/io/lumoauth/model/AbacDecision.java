package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/** The outcome of evaluating ABAC policies for one resource/action pair. */
public record AbacDecision(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("reason") String reason,
    @JsonProperty("matchedPolicies") List<AbacMatchedPolicy> matchedPolicies,
    Map<String, Object> raw
) implements RawPayload<AbacDecision> {

    public AbacDecision {
        matchedPolicies = Models.list(matchedPolicies);
        raw = Models.map(raw);
    }

    @Override
    public AbacDecision withRaw(Map<String, Object> newRaw) {
        return new AbacDecision(allowed, reason, matchedPolicies, newRaw);
    }
}
