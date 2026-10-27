package io.lumoauth.resources;

import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.model.McpToken;
import io.lumoauth.model.TokenExchangeRequest;
import io.lumoauth.model.TokenResponse;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Exchanges the caller's token for one bound to a secured MCP server (RFC 8693).
 *
 * <p>The server ID is the MCP server's https URL, which is its RFC 8707 resource identifier.
 * The SDK sends it as {@code resource}, and LumoAuth sets the issued token's {@code aud} from it.
 * The SDK also sends it as {@code audience}, which LumoAuth ignores.
 *
 * <pre>{@code
 * String token = lumo.mcp().token("https://mcp.example.com/mcp");
 * }</pre>
 */
public final class McpResource {

    private final HttpTransport http;
    private final AuthResource auth;

    public McpResource(HttpTransport http, AuthResource auth) {
        this.http = http;
        this.auth = auth;
    }

    /** An access token bound to one MCP server (its https URL), exchanging the client's own bearer token. */
    public String token(String serverId) {
        return tokenDetailed(serverId, null).accessToken();
    }

    /** An access token bound to one MCP server (its https URL), exchanging the given subject token. */
    public String token(String serverId, String subjectToken) {
        return tokenDetailed(serverId, subjectToken).accessToken();
    }

    /** {@link #token} with the full response: lifetime, type, and granted scope. */
    public McpToken tokenDetailed(String serverId, String subjectToken) {
        requireResourceUri(serverId);
        String token = subjectToken;
        if (token == null || token.isBlank()) {
            token = http.bearerToken().orElseThrow(() -> new LumoAuthConfigException(
                "MCP token exchange needs a subject token - authenticate first, or pass one explicitly"));
        }
        TokenResponse response = auth.tokenExchange(TokenExchangeRequest.of(token).resource(serverId).audience(serverId));
        return new McpToken(response.accessToken(), response.tokenType(), response.expiresIn(), response.scope());
    }

    /**
     * Checks that the MCP server ID is an absolute http(s) URI without a fragment. LumoAuth refuses any other
     * {@code resource} value with 400 {@code invalid_target}. (LumoAuth accepts http only for localhost and
     * private hosts; it enforces that rule itself.)
     */
    static void requireResourceUri(String serverId) {
        String hint = "the MCP server ID must be the server's https URL (its RFC 8707 resource identifier),"
            + " e.g. \"https://mcp.example.com/mcp\"";
        if (serverId == null || serverId.isBlank()) {
            throw new LumoAuthValidationException("a server ID is required: " + hint);
        }
        URI uri;
        try {
            uri = new URI(serverId);
        } catch (URISyntaxException e) {
            throw new LumoAuthValidationException(hint + "; got \"" + serverId + "\"");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!uri.isAbsolute() || !(scheme.equals("https") || scheme.equals("http"))
            || uri.getHost() == null || uri.getHost().isEmpty() || uri.getRawFragment() != null) {
            throw new LumoAuthValidationException(hint + "; got \"" + serverId + "\"");
        }
    }
}
