package io.lumoauth.model;

import java.util.List;

/** An audience-scoped token for a secured MCP server. */
public record McpToken(String accessToken, String tokenType, int expiresIn, String scope) {
    public List<String> scopes() {
        return Models.splitScopes(scope);
    }
}
