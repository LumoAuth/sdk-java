package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An OIDC UserInfo response. Agent principals additionally carry
 * {@link #capabilities()} and {@link #budgetPolicy()}; every other claim is in {@link #raw()}.
 */
public record UserInfo(
    @JsonProperty("sub") String sub,
    @JsonProperty("email") String email,
    @JsonProperty("email_verified") boolean emailVerified,
    @JsonProperty("name") String name,
    @JsonProperty("given_name") String givenName,
    @JsonProperty("family_name") String familyName,
    @JsonProperty("picture") String picture,
    @JsonProperty("preferred_username") String preferredUsername,
    @JsonProperty("roles") List<String> roles,
    @JsonProperty("agent_id") String agentId,
    @JsonProperty("client_id") String clientId,
    @JsonProperty("capabilities") List<String> capabilities,
    @JsonProperty("budget_policy") AgentBudget budgetPolicy,
    Map<String, Object> raw
) implements RawPayload<UserInfo> {

    public UserInfo {
        roles = Models.list(roles);
        capabilities = Models.list(capabilities);
        raw = Models.map(raw);
    }

    @Override
    public UserInfo withRaw(Map<String, Object> newRaw) {
        return new UserInfo(sub, email, emailVerified, name, givenName, familyName, picture,
            preferredUsername, roles, agentId, clientId, capabilities, budgetPolicy, newRaw);
    }

    /** True for agent principals (the response carries an agent_id). */
    public boolean isAgent() {
        return agentId != null && !agentId.isEmpty();
    }

    /** Any claim by name, including ones not modelled as a component. */
    public Optional<Object> claim(String name) {
        return Optional.ofNullable(raw.get(name));
    }
}
