package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * The budget policy attached to an agent, with today's usage.
 *
 * @param reportedExhausted the server's own verdict ({@code exhausted}): true when any limit
 *                          (calls, tokens or cost, per hour, day or month) is reached; null when the
 *                          server did not report it
 */
public record AgentBudget(
    @JsonProperty("max_tokens_per_day") int maxTokensPerDay,
    @JsonProperty("tokens_used_today") int tokensUsedToday,
    @JsonProperty("exhausted") Boolean reportedExhausted,
    Map<String, Object> raw
) implements RawPayload<AgentBudget> {

    /** The empty policy: no cap, never exhausted. */
    public static final AgentBudget NONE = new AgentBudget(0, 0, null, null);

    public AgentBudget {
        raw = Models.map(raw);
    }

    /** A policy without a server verdict (kept for source compatibility). */
    public AgentBudget(int maxTokensPerDay, int tokensUsedToday, Map<String, Object> raw) {
        this(maxTokensPerDay, tokensUsedToday, null, raw);
    }

    @Override
    public AgentBudget withRaw(Map<String, Object> newRaw) {
        return new AgentBudget(maxTokensPerDay, tokensUsedToday, reportedExhausted, newRaw);
    }

    /**
     * Whether the agent's budget is spent, so the next metered call would get 429. Uses the
     * server's verdict when reported (any limit, any window); otherwise compares the daily token
     * cap with today's usage, and a policy without a daily cap is never exhausted.
     */
    public boolean exhausted() {
        if (reportedExhausted != null) {
            return reportedExhausted;
        }
        return maxTokensPerDay > 0 && tokensUsedToday >= maxTokensPerDay;
    }
}
