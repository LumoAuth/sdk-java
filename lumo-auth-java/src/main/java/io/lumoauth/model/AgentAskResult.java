package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/** The decision returned by the Ask API. */
public record AgentAskResult(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("action") String action,
    @JsonProperty("reason") String reason,
    @JsonProperty("audit_id") String auditId,
    @JsonProperty("context") Map<String, Object> context,
    Map<String, Object> raw
) implements RawPayload<AgentAskResult> {

    public AgentAskResult {
        context = Models.map(context);
        raw = Models.map(raw);
    }

    @Override
    public AgentAskResult withRaw(Map<String, Object> newRaw) {
        return new AgentAskResult(allowed, action, reason, auditId, context, newRaw);
    }
}
