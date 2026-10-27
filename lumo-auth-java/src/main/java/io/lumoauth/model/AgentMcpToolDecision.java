package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * LumoAuth's answer when an agent asks whether it may run a tool on an MCP server.
 *
 * <p>A deny is a normal result with {@code allowed} set to false. The SDK does not throw for it.
 *
 * @param allowed  whether the agent may run the tool
 * @param agentId  the agent's ID ({@code agt_...})
 * @param resource the checked resource: type {@code mcp_tool}, ID {@code <serverId>/<tool>}
 */
public record AgentMcpToolDecision(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("agent_id") String agentId,
    @JsonProperty("resource") McpToolDecision.Resource resource,
    Map<String, Object> raw
) implements RawPayload<AgentMcpToolDecision> {

    public AgentMcpToolDecision {
        raw = Models.map(raw);
    }

    @Override
    public AgentMcpToolDecision withRaw(Map<String, Object> newRaw) {
        return new AgentMcpToolDecision(allowed, agentId, resource, newRaw);
    }
}
