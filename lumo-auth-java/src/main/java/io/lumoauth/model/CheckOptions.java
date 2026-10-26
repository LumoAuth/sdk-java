package io.lumoauth.model;

import java.util.Map;

/**
 * Optional arguments shared by every RBAC check.
 *
 * <pre>{@code
 * lumo.permissions().check("document.edit", CheckOptions.forUser("0199a2c4-…"));
 * lumo.permissions().check("document.edit", CheckOptions.forAgent("agt_c8ed16883d441af8"));
 * lumo.permissions().check("document.edit", CheckOptions.withContext(Map.of("pep", Map.of("ip", ip))));
 * }</pre>
 *
 * <p>Without a user or an agent, the check is about the caller: the owner of the API key,
 * or the subject of the access token. To ask about someone else, the caller needs the
 * {@code authz:check} scope (an API key can hold it) or the {@code authz.check} permission.
 * The SDK sends the subject as {@code "subject": {"type": "user"|"agent", "id": …}}.
 * Without that right the server answers 403 {@code INSUFFICIENT_PERMISSIONS}; an id that
 * is not in the organization gets 404 {@code SUBJECT_NOT_FOUND}.
 *
 * @param context attributes for ABAC evaluation alongside the RBAC decision
 * @param userId  the LumoAuth user id (a UUID, the {@code sub} claim of that user's tokens)
 *                of the user that the check is about
 * @param agentId the agent id ({@code agt_…}) of the agent that the check is about;
 *                set at most one of {@code userId} and {@code agentId}
 */
public record CheckOptions(Map<String, Object> context, String userId, String agentId) {

    public static final CheckOptions NONE = new CheckOptions(null, null, null);

    public CheckOptions {
        context = Models.map(context);
        userId = Models.blankToNull(userId);
        agentId = Models.blankToNull(agentId);
        if (userId != null && agentId != null) {
            throw new IllegalArgumentException("set either userId or agentId, not both");
        }
    }

    /** The 1.0 two-argument form: context and a user id. */
    public CheckOptions(Map<String, Object> context, String userId) {
        this(context, userId, null);
    }

    /** A check about the user with this LumoAuth user id (UUID). */
    public static CheckOptions forUser(String userId) {
        return new CheckOptions(null, userId, null);
    }

    /** A check about the agent with this agent id ({@code agt_…}). */
    public static CheckOptions forAgent(String agentId) {
        return new CheckOptions(null, null, agentId);
    }

    public static CheckOptions withContext(Map<String, Object> context) {
        return new CheckOptions(context, null, null);
    }

    public CheckOptions context(Map<String, Object> newContext) {
        return new CheckOptions(newContext, userId, agentId);
    }

    /** A copy about this user; clears any agent. */
    public CheckOptions user(String newUserId) {
        return new CheckOptions(context, newUserId, null);
    }

    /** A copy about this agent; clears any user. */
    public CheckOptions agent(String newAgentId) {
        return new CheckOptions(context, null, newAgentId);
    }
}
