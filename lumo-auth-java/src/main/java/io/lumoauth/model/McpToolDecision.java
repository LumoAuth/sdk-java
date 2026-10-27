package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * LumoAuth's answer to "may this subject run this tool on this MCP server?".
 *
 * <p>A deny is a normal result with {@code allowed} set to false. The SDK does not throw for it.
 *
 * @param allowed  whether the subject may run the tool
 * @param subject  the subject that was checked, as LumoAuth resolved it
 * @param resource the checked resource: type {@code mcp_tool}, ID {@code <serverId>/<tool>}
 */
public record McpToolDecision(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("subject") Subject subject,
    @JsonProperty("resource") Resource resource,
    Map<String, Object> raw
) implements RawPayload<McpToolDecision> {

    /** A user or an agent. */
    public record Subject(@JsonProperty("type") String type, @JsonProperty("id") String id) {
    }

    /** The checked MCP tool. */
    public record Resource(@JsonProperty("type") String type, @JsonProperty("id") String id) {
    }

    public McpToolDecision {
        raw = Models.map(raw);
    }

    @Override
    public McpToolDecision withRaw(Map<String, Object> newRaw) {
        return new McpToolDecision(allowed, subject, resource, newRaw);
    }
}
