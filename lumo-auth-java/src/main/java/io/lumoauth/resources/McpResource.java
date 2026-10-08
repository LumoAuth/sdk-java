package io.lumoauth.resources;

import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.model.McpToken;
import io.lumoauth.model.TokenExchangeRequest;
import io.lumoauth.model.TokenResponse;

/**
 * Exchanges the caller's token for one scoped to a secured MCP server
 * (RFC 8693, with the server id as the audience).
 *
 * <pre>{@code
 * String token = lumo.mcp().token("urn:mcp:financial-data");
 * }</pre>
 */
public final class McpResource {

    private final HttpTransport http;
    private final AuthResource auth;

    public McpResource(HttpTransport http, AuthResource auth) {
        this.http = http;
        this.auth = auth;
    }

    /** An access token scoped to one MCP server, exchanging the client's own bearer token. */
    public String token(String serverId) {
        return tokenDetailed(serverId, null).accessToken();
    }

    /** An access token scoped to one MCP server, exchanging the given subject token. */
    public String token(String serverId, String subjectToken) {
        return tokenDetailed(serverId, subjectToken).accessToken();
    }

    /** {@link #token} with the full response: lifetime, type, and granted scope. */
    public McpToken tokenDetailed(String serverId, String subjectToken) {
        if (serverId == null || serverId.isBlank()) {
            throw new LumoAuthValidationException(
                "a server ID is required (the MCP server's audience, e.g. \"urn:mcp:financial-data\")");
        }
        String token = subjectToken;
        if (token == null || token.isBlank()) {
            token = http.bearerToken().orElseThrow(() -> new LumoAuthConfigException(
                "MCP token exchange needs a subject token - authenticate first, or pass one explicitly"));
        }
        TokenResponse response = auth.tokenExchange(TokenExchangeRequest.of(token).audience(serverId));
        return new McpToken(response.accessToken(), response.tokenType(), response.expiresIn(), response.scope());
    }
}
