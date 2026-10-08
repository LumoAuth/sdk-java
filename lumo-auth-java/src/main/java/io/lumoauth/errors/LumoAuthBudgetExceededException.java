package io.lumoauth.errors;

import io.lumoauth.model.AgentBudget;

/** The agent's budget policy blocks the action. {@link #budget()} is the policy that did. */
public class LumoAuthBudgetExceededException extends LumoAuthException {

    private final transient AgentBudget budget;

    public LumoAuthBudgetExceededException(AgentBudget budget) {
        super(ErrorCodes.BUDGET_EXCEEDED, "agent budget exceeded", null);
        this.budget = budget;
    }

    public AgentBudget budget() {
        return budget;
    }
}
