package io.lumoauth.resources;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthPermissionDeniedException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.internal.Json;
import io.lumoauth.model.McpToken;
import io.lumoauth.model.McpToolDecision;
import io.lumoauth.model.TokenExchangeRequest;
import io.lumoauth.model.TokenResponse;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * MCP helpers: tokens for a secured MCP server, and per-tool checks for the MCP server itself.
 *
 * <p><b>Tokens.</b> {@link #token} exchanges the caller's token for one bound to a single MCP server
 * (RFC 8693). Pass the server's registered Resource URI, which is its RFC 8707 resource identifier.
 * The SDK sends it as {@code resource}, and LumoAuth sets the issued token's {@code aud} from it.
 * The SDK also sends it as {@code audience}, which LumoAuth ignores. The token names exactly one
 * MCP server and works only at that server: LumoAuth's own API rejects it. This method does not
 * send a DPoP proof, so a server that requires DPoP needs a DPoP-bound exchange instead.
 *
 * <pre>{@code
 * String token = lumo.mcp().token("https://mcp.example.com/mcp");
 * }</pre>
 *
 * <p><b>Per-tool checks.</b> {@link #authorizeTool} is for the MCP server. The client must use the
 * MCP server's own client-credentials token with the scope {@code mcp:authorize}, never the token
 * that the caller sent. A deny comes back as a result with {@code allowed} set to false.
 *
 * <pre>{@code
 * McpToolDecision d = lumo.mcp().authorizeTool("mcp_0123456789abcdef01234567", "user", sub, "search");
 * if (!d.allowed()) { ... }
 * }</pre>
 */
public final class McpResource {

    /** The longest tool name that LumoAuth accepts. */
    public static final int MAX_TOOL_LENGTH = 80;

    private final HttpTransport http;
    private final AuthResource auth;

    public McpResource(HttpTransport http, AuthResource auth) {
        this.http = http;
        this.auth = auth;
    }

    /**
     * An access token bound to one MCP server, exchanging the client's own bearer token.
     *
     * @param serverId the MCP server's registered Resource URI (its https URL), not its {@code mcp_...} ID
     */
    public String token(String serverId) {
        return tokenDetailed(serverId, null).accessToken();
    }

    /**
     * An access token bound to one MCP server, exchanging the given subject token.
     *
     * @param serverId the MCP server's registered Resource URI (its https URL), not its {@code mcp_...} ID
     */
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
     * Asks whether a user or an agent may run one tool on this MCP server.
     *
     * <p>Call it from the MCP server, with the server's own client-credentials token (scope
     * {@code mcp:authorize}). The server's client must be one of the MCP server's tool authorizers.
     * Never pass on the token that the caller sent. A deny returns {@code allowed == false} and does
     * not throw. A 403 without a decision (for example {@code insufficient_scope}) throws
     * {@link LumoAuthPermissionDeniedException}.
     *
     * @param serverId    the registered MCP server ID, e.g. {@code mcp_0123456789abcdef01234567}, not its URL
     * @param subjectType {@code user} or {@code agent}
     * @param subjectId   the {@code sub} of the verified MCP token: a user ID, or an agent ID
     *                    ({@code agt_...} or {@code agent_agt_...})
     * @param tool        the tool name, at most 80 characters, without {@code / : # *}
     */
    public McpToolDecision authorizeTool(String serverId, String subjectType, String subjectId, String tool) {
        requireToolPart("server ID", serverId);
        requireToolName(tool);
        if (!"user".equals(subjectType) && !"agent".equals(subjectType)) {
            throw new LumoAuthValidationException("the subject type must be \"user\" or \"agent\"; got \"" + subjectType + "\"");
        }
        if (subjectId == null || subjectId.isBlank()) {
            throw new LumoAuthValidationException("a subject ID is required");
        }
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("type", subjectType);
        subject.put("id", subjectId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", subject);
        body.put("tool", tool);
        return decision(http, Routes.MCP_AUTHORIZE_TOOL, Map.of("serverId", serverId), body, McpToolDecision.class);
    }

    /**
     * Sends a per-tool check and decodes the decision. A 403 whose JSON body has {@code "allowed": false}
     * is a decision, not an error. Every other error status throws as usual.
     */
    static <T> T decision(HttpTransport http, String routeName, Map<String, String> params,
                          Map<String, Object> body, Class<T> type) {
        Routes.Route route = http.resolve(routeName, params);
        JsonNode node;
        try {
            node = http.sendNode(route.method(), route.path(), ApiRequest.json(body));
        } catch (LumoAuthPermissionDeniedException e) {
            Map<String, Object> denied = e.statusCode() == 403 ? e.bodyAsMap().orElse(null) : null;
            if (denied == null || !Boolean.FALSE.equals(denied.get("allowed"))) {
                throw e;
            }
            node = Json.mapper().valueToTree(denied);
        }
        T result = Json.convert(node, type, route.path());
        if (result == null) {
            throw new LumoAuthValidationException("could not decode the response from " + route.path() + ": empty body");
        }
        return result;
    }

    /** Checks a tool name: required, at most 80 characters, without {@code / : # *}. */
    static void requireToolName(String tool) {
        requireToolPart("tool name", tool);
        if (tool.length() > MAX_TOOL_LENGTH) {
            throw new LumoAuthValidationException("the tool name must be at most " + MAX_TOOL_LENGTH + " characters");
        }
    }

    /** Checks a server ID or tool name: required, and without {@code / : # *}. */
    static void requireToolPart(String what, String value) {
        if (value == null || value.isBlank()) {
            throw new LumoAuthValidationException("a " + what + " is required");
        }
        for (char c : new char[] {'/', ':', '#', '*'}) {
            if (value.indexOf(c) >= 0) {
                throw new LumoAuthValidationException("the " + what + " must not contain '" + c + "'; got \"" + value + "\"");
            }
        }
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
