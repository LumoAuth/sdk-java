package io.lumoauth;

import io.lumoauth.errors.LumoAuthConfigException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Central registry of every LumoAuth endpoint this SDK talks to.
 *
 * <p>GENERATED from {@code sdk-contract/routes.json} by
 * {@code sdk-contract/scripts/gen-java-routes.py}. Do not edit by hand: the
 * contract test fails when this file is stale. Paths use OpenAPI
 * {@code {camelCase}} placeholders. Add endpoints to the contract, then regenerate.
 */
public final class Routes {

    /** One endpoint: an HTTP method and a path template. */
    public record Route(String method, String path) {
    }

    /** The org-scoped API prefix shared by most routes. */
    public static final String ORG_SCOPED_PREFIX = "/orgs/{orgId}/api/v1";

    // ── aauth: AAuth cryptographic agent identity: token endpoint, discovery, JWKS
    public static final String AAUTH_AGENT_AUTH = "aauth.agentAuth";
    public static final String AAUTH_AGENT_METADATA = "aauth.agentMetadata";
    public static final String AAUTH_AGENT_TOKEN = "aauth.agentToken";
    public static final String AAUTH_ISSUER_METADATA = "aauth.issuerMetadata";
    public static final String AAUTH_JWKS = "aauth.jwks";
    public static final String AAUTH_TOKEN_REVOKE = "aauth.tokenRevoke";
    public static final String WELLKNOWN_AAUTH_ISSUER = "wellknown.aauthIssuer";
    // ── abac: Attribute-based checks and attribute management (org-scoped)
    public static final String ABAC_ATTRIBUTE_DEFINITIONS = "abac.attributeDefinitions";
    public static final String ABAC_CHECK = "abac.check";
    public static final String ABAC_CHECK_BULK = "abac.checkBulk";
    public static final String ABAC_MY_ATTRIBUTES = "abac.myAttributes";
    public static final String ABAC_RESOURCE_ATTRIBUTES = "abac.resourceAttributes";
    public static final String ABAC_SET_RESOURCE_ATTRIBUTE = "abac.setResourceAttribute";
    public static final String ABAC_SET_USER_ATTRIBUTE = "abac.setUserAttribute";
    // ── agents: Agent identity: Ask API, self-info, registration
    public static final String AGENTS_ASK = "agents.ask";
    public static final String AGENTS_AUTHORIZE_MCP_TOOL = "agents.authorizeMcpTool";
    public static final String AGENTS_ME = "agents.me";
    public static final String AGENTS_REGISTER = "agents.register";
    // ── approvals: Push approval for actions
    public static final String APPROVALS_CREATE = "approvals.create";
    public static final String APPROVALS_STATUS = "approvals.status";
    // ── auth: OAuth 2.1 / OIDC token-endpoint flows and userinfo
    public static final String OAUTH_AUTHORIZE = "oauth.authorize";
    public static final String OAUTH_LOGIN_JSON = "oauth.loginJson";
    public static final String OAUTH_LOGOUT = "oauth.logout";
    public static final String OAUTH_REVOKE = "oauth.revoke";
    public static final String OAUTH_TOKEN = "oauth.token";
    public static final String OAUTH_USERINFO = "oauth.userinfo";
    // ── jit: Just-in-time permissions: tasks, requests, short-lived tokens
    public static final String JIT_COMPLETE_TASK = "jit.completeTask";
    public static final String JIT_CREATE_TASK = "jit.createTask";
    public static final String JIT_EVALUATE_TASK = "jit.evaluateTask";
    public static final String JIT_PENDING = "jit.pending";
    public static final String JIT_REQUEST = "jit.request";
    public static final String JIT_REQUEST_STATUS = "jit.requestStatus";
    public static final String JIT_TOKEN = "jit.token";
    // ── mcp: MCP: token exchange for one MCP server (built on oauth.token) and the per-tool check that an MCP server asks with its own client-credentials token
    public static final String MCP_AUTHORIZE_TOOL = "mcp.authorizeTool";
    // ── permissions: RBAC permission checks (bearer-scoped, org inferred from the credential)
    public static final String PERMISSIONS_CHECK = "permissions.check";
    public static final String PERMISSIONS_CHECK_ALL = "permissions.checkAll";
    public static final String PERMISSIONS_CHECK_ANY = "permissions.checkAny";
    public static final String PERMISSIONS_CHECK_BULK = "permissions.checkBulk";
    public static final String PERMISSIONS_LIST = "permissions.list";
    // ── webauth: Browser sign-in helpers served by the web firewall
    public static final String WEB_CHECK_EMAIL = "web.checkEmail";
    public static final String WEB_MAGIC_LINK = "web.magicLink";
    // ── zanzibar: Relationship-based checks and expansion
    public static final String ZANZIBAR_CHECK = "zanzibar.check";
    public static final String ZANZIBAR_EXPAND = "zanzibar.expand";

    private static final Map<String, Route> ROUTES = Map.ofEntries(
        Map.entry("aauth.agentAuth", new Route("GET", "/orgs/{orgId}/api/v1/aauth/agent/auth")),
        Map.entry("aauth.agentMetadata", new Route("GET", "/orgs/{orgId}/api/v1/.well-known/aauth-agent")),
        Map.entry("aauth.agentToken", new Route("POST", "/orgs/{orgId}/api/v1/aauth/agent/token")),
        Map.entry("aauth.issuerMetadata", new Route("GET", "/orgs/{orgId}/api/v1/.well-known/aauth-issuer")),
        Map.entry("aauth.jwks", new Route("GET", "/orgs/{orgId}/api/v1/aauth/jwks.json")),
        Map.entry("aauth.tokenRevoke", new Route("POST", "/orgs/{orgId}/api/v1/aauth/token/revoke")),
        Map.entry("wellknown.aauthIssuer", new Route("GET", "/.well-known/aauth-issuer")),
        Map.entry("abac.attributeDefinitions", new Route("GET", "/orgs/{orgId}/api/v1/abac/attribute-definitions")),
        Map.entry("abac.check", new Route("POST", "/orgs/{orgId}/api/v1/abac/check")),
        Map.entry("abac.checkBulk", new Route("POST", "/orgs/{orgId}/api/v1/abac/check-bulk")),
        Map.entry("abac.myAttributes", new Route("GET", "/orgs/{orgId}/api/v1/abac/my-attributes")),
        Map.entry("abac.resourceAttributes", new Route("GET", "/orgs/{orgId}/api/v1/abac/resources/{resourceType}/{resourceId}/attributes")),
        Map.entry("abac.setResourceAttribute", new Route("PUT", "/orgs/{orgId}/api/v1/abac/resources/{resourceType}/{resourceId}/attributes/{attributeSlug}")),
        Map.entry("abac.setUserAttribute", new Route("PUT", "/orgs/{orgId}/api/v1/abac/users/{userId}/attributes/{attributeSlug}")),
        Map.entry("agents.ask", new Route("POST", "/orgs/{orgId}/api/v1/agents/ask")),
        Map.entry("agents.authorizeMcpTool", new Route("POST", "/orgs/{orgId}/api/v1/agents/me/mcp/authorize")),
        Map.entry("agents.me", new Route("GET", "/orgs/{orgId}/api/v1/agents/me")),
        Map.entry("agents.register", new Route("POST", "/orgs/{orgId}/api/v1/agents/register")),
        Map.entry("approvals.create", new Route("POST", "/orgs/{orgId}/api/v1/agents/me/approvals")),
        Map.entry("approvals.status", new Route("GET", "/orgs/{orgId}/api/v1/agents/me/approvals/{token}/status")),
        Map.entry("oauth.authorize", new Route("GET", "/orgs/{orgId}/api/v1/oauth/authorize")),
        Map.entry("oauth.loginJson", new Route("POST", "/orgs/{orgId}/api/v1/oauth/login/json")),
        Map.entry("oauth.logout", new Route("GET", "/orgs/{orgId}/api/v1/oauth/logout")),
        Map.entry("oauth.revoke", new Route("POST", "/orgs/{orgId}/api/v1/oauth/revoke")),
        Map.entry("oauth.token", new Route("POST", "/orgs/{orgId}/api/v1/oauth/token")),
        Map.entry("oauth.userinfo", new Route("GET", "/orgs/{orgId}/api/v1/oauth/userinfo")),
        Map.entry("jit.completeTask", new Route("POST", "/orgs/{orgId}/api/v1/jit/task/{taskId}/complete")),
        Map.entry("jit.createTask", new Route("POST", "/orgs/{orgId}/api/v1/jit/task")),
        Map.entry("jit.evaluateTask", new Route("POST", "/orgs/{orgId}/api/v1/jit/task/{taskId}/evaluate")),
        Map.entry("jit.pending", new Route("GET", "/orgs/{orgId}/api/v1/jit/pending")),
        Map.entry("jit.request", new Route("POST", "/orgs/{orgId}/api/v1/jit/request")),
        Map.entry("jit.requestStatus", new Route("GET", "/orgs/{orgId}/api/v1/jit/request/{requestId}/status")),
        Map.entry("jit.token", new Route("POST", "/orgs/{orgId}/api/v1/jit/request/{requestId}/token")),
        Map.entry("mcp.authorizeTool", new Route("POST", "/orgs/{orgId}/api/v1/mcp/servers/{serverId}/tools/authorize")),
        Map.entry("permissions.check", new Route("POST", "/api/v1/authz/check")),
        Map.entry("permissions.checkAll", new Route("POST", "/api/v1/authz/check-all")),
        Map.entry("permissions.checkAny", new Route("POST", "/api/v1/authz/check-any")),
        Map.entry("permissions.checkBulk", new Route("POST", "/api/v1/authz/check-bulk")),
        Map.entry("permissions.list", new Route("GET", "/api/v1/authz/permissions")),
        Map.entry("web.checkEmail", new Route("POST", "/orgs/{orgId}/check-email")),
        Map.entry("web.magicLink", new Route("POST", "/orgs/{orgId}/magic-link")),
        Map.entry("zanzibar.check", new Route("POST", "/api/v1/authz/zanzibar/check")),
        Map.entry("zanzibar.expand", new Route("POST", "/api/v1/authz/zanzibar/expand"))
    );

    private Routes() {
    }

    /** Every registered route name, sorted. */
    public static Set<String> names() {
        return Collections.unmodifiableSet(new TreeSet<>(ROUTES.keySet()));
    }

    /** The route name to method/path map, in registry form. */
    public static Map<String, Route> all() {
        return ROUTES;
    }

    /** Looks a route up by name; unknown names are a configuration error. */
    public static Route get(String name) {
        Route route = ROUTES.get(name);
        if (route == null) {
            throw new LumoAuthConfigException("Unknown route \"" + name + "\"");
        }
        return route;
    }

    /**
     * Fills {@code {param}} placeholders in a path template; values are URL-encoded.
     * A missing or empty value throws a {@link LumoAuthConfigException}, so an absent
     * org ID fails loudly at the call site rather than as a server-side 404.
     */
    public static String buildPath(String template, Map<String, String> params) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < template.length()) {
            int open = template.indexOf('{', i);
            if (open < 0) {
                out.append(template, i, template.length());
                break;
            }
            int close = template.indexOf('}', open);
            if (close < 0) {
                out.append(template, i, template.length());
                break;
            }
            String name = template.substring(open + 1, close);
            String value = params == null ? null : params.get(name);
            if (value == null || value.isEmpty()) {
                throw new LumoAuthConfigException(
                    "Missing route parameter \"" + name + "\" for path " + template);
            }
            out.append(template, i, open).append(pathEncode(value));
            i = close + 1;
        }
        return out.toString();
    }

    /** Looks a route up and builds its concrete path in one call. */
    public static String path(String name, Map<String, String> params) {
        return buildPath(get(name).path(), params);
    }

    /** Percent-encodes one path segment (RFC 3986), leaving unreserved characters alone. */
    static String pathEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
