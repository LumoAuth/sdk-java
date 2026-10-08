package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/** The budget policy attached to an agent. */
public record AgentBudget(
    @JsonProperty("max_tokens_per_day") int maxTokensPerDay,
    @JsonProperty("tokens_used_today") int tokensUsedToday,
    Map<String, Object> raw
) implements RawPayload<AgentBudget> {

    /** The empty policy: no cap, never exhausted. */
    public static final AgentBudget NONE = new AgentBudget(0, 0, null);

    public AgentBudget {
        raw = Models.map(raw);
    }

    @Override
    public AgentBudget withRaw(Map<String, Object> newRaw) {
        return new AgentBudget(maxTokensPerDay, tokensUsedToday, newRaw);
    }

    /** Whether the daily token budget has been reached. A policy without a daily cap is never exhausted. */
    public boolean exhausted() {
        return maxTokensPerDay > 0 && tokensUsedToday >= maxTokensPerDay;
    }
}
