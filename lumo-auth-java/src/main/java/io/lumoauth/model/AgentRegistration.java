package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/** The response to registering an agent. */
public record AgentRegistration(
    @JsonProperty("agent_id") String agentId,
    @JsonProperty("client_id") String clientId,
    @JsonProperty("name") String name,
    @JsonProperty("status") String status,
    @JsonProperty("workload_identity") String workloadIdentity,
    Map<String, Object> raw
) implements RawPayload<AgentRegistration> {

    public AgentRegistration {
        raw = Models.map(raw);
    }

    @Override
    public AgentRegistration withRaw(Map<String, Object> newRaw) {
        return new AgentRegistration(agentId, clientId, name, status, workloadIdentity, newRaw);
    }
}
