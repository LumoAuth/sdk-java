package io.lumoauth.resources;

import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.model.AgentAskResult;
import io.lumoauth.model.AgentBudget;
import io.lumoauth.model.AgentIdentity;
import io.lumoauth.model.AgentRegistration;
import io.lumoauth.model.RegisterAgentRequest;
import io.lumoauth.model.UserInfo;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Agent identity: the Ask API for preflight authorization, self-inspection,
 * and registration.
 *
 * <pre>{@code
 * AgentAskResult decision = lumo.agents().ask("document.read", Map.of("id", "doc_99"));
 * if (!decision.allowed()) { throw new IllegalStateException(decision.reason()); }
 * }</pre>
 */
public final class AgentsResource {

    private final HttpTransport http;
    private final AuthResource auth;

    public AgentsResource(HttpTransport http, AuthResource auth) {
        this.http = http;
        this.auth = auth;
    }

    /**
     * Asks whether the agent may perform an action. Writes an audit record either way.
     * {@code ip}, {@code userAgent}, {@code requestMethod} and {@code requestPath} in the context always
     * describe the request LumoAuth received; values you pass under those names are kept under {@code pep}.
     */
    public AgentAskResult ask(String action) {
        return ask(action, null);
    }

    public AgentAskResult ask(String action, Map<String, Object> context) {
        if (action == null || action.isBlank()) {
            throw new LumoAuthValidationException("an action is required");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("action", action);
        if (context != null && !context.isEmpty()) {
            body.put("context", context);
        }
        return http.call(Routes.AGENTS_ASK, null, ApiRequest.json(body), AgentAskResult.class);
    }

    /** {@link #ask} reduced to a boolean. */
    public boolean isAllowed(String action) {
        return ask(action, null).allowed();
    }

    public boolean isAllowed(String action, Map<String, Object> context) {
        return ask(action, context).allowed();
    }

    /**
     * The calling agent's own identity, capabilities, and workspace. For an agent credential the
     * capabilities are the agent's capability roles; a user access token without {@code authz:read}
     * gets an empty list.
     */
    public AgentIdentity me() {
        return http.call(Routes.AGENTS_ME, null, null, AgentIdentity.class);
    }

    /** Creates or updates the agent's record in the organization directory. */
    public AgentRegistration register(RegisterAgentRequest params) {
        return http.call(Routes.AGENTS_REGISTER, null, ApiRequest.json(params.toBody()), AgentRegistration.class);
    }

    /** The agent's claims from the UserInfo endpoint: capabilities and the budget policy. */
    public UserInfo info() {
        return auth.userinfo();
    }

    /** The capability slugs granted to the agent. */
    public List<String> capabilities() {
        return info().capabilities();
    }

    /** The agent's budget policy; {@link AgentBudget#NONE} when there is none. */
    public AgentBudget budget() {
        AgentBudget budget = info().budgetPolicy();
        return budget == null ? AgentBudget.NONE : budget;
    }
}
