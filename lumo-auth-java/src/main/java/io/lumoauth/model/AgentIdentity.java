package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The agent's own identity, capabilities, and workspace. */
public record AgentIdentity(
    @JsonProperty("identity") Map<String, Object> identity,
    @JsonProperty("capabilities") List<String> capabilities,
    @JsonProperty("workspace") Map<String, Object> workspace,
    Map<String, Object> raw
) implements RawPayload<AgentIdentity> {

    public AgentIdentity {
        identity = Models.map(identity);
        capabilities = Models.list(capabilities);
        workspace = Models.map(workspace);
        raw = Models.map(raw);
    }

    @Override
    public AgentIdentity withRaw(Map<String, Object> newRaw) {
        return new AgentIdentity(identity, capabilities, workspace, newRaw);
    }

    /** The agent's identity ID, when the server sent one. */
    public Optional<String> id() {
        Object id = identity.get("id");
        return id == null ? Optional.empty() : Optional.of(String.valueOf(id));
    }
}
