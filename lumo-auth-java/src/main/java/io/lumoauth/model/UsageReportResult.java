package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * The answer to a usage report ({@code POST /agents/me/usage}): what LumoAuth recorded, and the
 * agent's budget after it.
 *
 * @param recorded the tokens and cost added to the agent's budget windows
 * @param budget   the budget after the report, the same shape as UserInfo's {@code budget_policy};
 *                 {@link AgentBudget#exhausted()} means that the next metered call gets 429
 * @param raw      the complete decoded response
 */
public record UsageReportResult(
    @JsonProperty("recorded") Recorded recorded,
    @JsonProperty("budget") AgentBudget budget,
    Map<String, Object> raw
) implements RawPayload<UsageReportResult> {

    public UsageReportResult {
        recorded = recorded == null ? new Recorded(0, 0.0) : recorded;
        budget = budget == null ? AgentBudget.NONE : budget;
        raw = Models.map(raw);
    }

    @Override
    public UsageReportResult withRaw(Map<String, Object> newRaw) {
        return new UsageReportResult(recorded, budget, newRaw);
    }

    /**
     * The usage that LumoAuth recorded.
     *
     * @param tokens  model tokens
     * @param costUsd cost in USD
     */
    public record Recorded(
        @JsonProperty("tokens") long tokens,
        @JsonProperty("cost_usd") double costUsd
    ) {
    }
}
