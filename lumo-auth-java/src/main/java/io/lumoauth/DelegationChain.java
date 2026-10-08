package io.lumoauth;

import io.lumoauth.errors.LumoAuthApiException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.model.CodeExchangeRequest;
import io.lumoauth.model.ConsentUrlRequest;
import io.lumoauth.model.RefreshTokenRequest;
import io.lumoauth.model.RevokeRequest;
import io.lumoauth.model.TokenResponse;
import io.lumoauth.resources.DelegationResource;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages RFC 8693 token exchange for agents acting on behalf of users: the
 * Chain of Agency. It tracks one delegation per session ID through the full
 * lifecycle:
 *
 * <ol>
 *   <li><b>User consent</b>: {@link #consentUrl} then {@link #handleConsentCallback}
 *       (or {@link #setUserToken} for a token you already hold).</li>
 *   <li><b>Token exchange</b>: {@link #exchange} combines the user's token (subject)
 *       with the agent's (actor) into a delegated token carrying an {@code act} claim.</li>
 *   <li><b>Delegated requests</b>: {@link #request} calls APIs as "agent acting for user".</li>
 *   <li><b>Nested delegation</b>: {@link #delegateToSubAgent} adds a link to the chain.</li>
 *   <li><b>Revocation</b>: {@link #revoke} invalidates a session's tokens.</li>
 * </ol>
 *
 * <pre>{@code
 * DelegationChain chain = new DelegationChain(agent, "https://agent.example.com/callback");
 * String url = chain.consentUrl("session-1", List.of("read:documents"));
 * // ... the user completes consent, your callback receives `code` ...
 * chain.handleConsentCallback("session-1", code);
 * Map<String, Object> docs = chain.request("session-1", "GET", "/orgs/acme/api/v1/documents", null, Map.class);
 * }</pre>
 *
 * A {@code DelegationChain} is safe for concurrent use.
 */
public final class DelegationChain {

    private record UserTokens(String accessToken, String refreshToken, Instant expiresAt, List<String> scopes) {
        static UserTokens of(TokenResponse token) {
            Duration expiresIn = token.expiresIn() > 0 ? Duration.ofSeconds(token.expiresIn()) : Duration.ofHours(1);
            return new UserTokens(token.accessToken(), token.refreshToken(), Instant.now().plus(expiresIn), token.scopes());
        }

        boolean expired() {
            return expiresAt != null && Instant.now().isAfter(expiresAt);
        }
    }

    private final ConfidentialClient agent;
    private final String redirectUri;
    private final LumoAuth client;
    private final DelegationResource resource;
    private final Map<String, UserTokens> userTokens = new ConcurrentHashMap<>();
    private final Map<String, String> delegatedTokens = new ConcurrentHashMap<>();

    /**
     * A chain over an authenticated agent. {@code redirectUri} is the OAuth
     * callback the consent flow returns to; it may be null when tokens are
     * registered directly with {@link #setUserToken}.
     */
    public DelegationChain(ConfidentialClient agent, String redirectUri) {
        this.agent = agent;
        this.redirectUri = redirectUri;
        this.client = LumoAuth.builder()
            .baseUrl(agent.baseUrl())
            .orgId(agent.orgId())
            .apiKey(null)
            .withoutCredential()
            .build();
        this.resource = client.delegation();
    }

    // ── Step 1: user consent ──────────────────────────────────────────

    /**
     * The URL where the user grants the agent permission to act on their
     * behalf. {@code sessionId} correlates the consent with the later exchange;
     * the OAuth state defaults to {@code session:<sessionId>}.
     */
    public String consentUrl(String sessionId, List<String> scopes) {
        return consentUrl(sessionId, scopes, null);
    }

    public String consentUrl(String sessionId, List<String> scopes, String state) {
        requireSession(sessionId);
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new LumoAuthConfigException("a redirect URI is required for the consent flow - pass it to the constructor");
        }
        String effectiveState = state == null || state.isBlank() ? "session:" + sessionId : state;
        return resource.consentUrl(ConsentUrlRequest.of(agent.clientId(), redirectUri).scopes(scopes).state(effectiveState));
    }

    /** Exchanges the authorization code from the consent callback for the user's tokens and stores them under the session. */
    public void handleConsentCallback(String sessionId, String authorizationCode) {
        requireSession(sessionId);
        if (authorizationCode == null || authorizationCode.isBlank()) {
            throw new LumoAuthValidationException("an authorization code is required");
        }
        TokenResponse token = resource.exchangeCode(
            CodeExchangeRequest.of(authorizationCode, redirectUri, agent.clientId()).clientSecret(agent.clientSecret()));
        userTokens.put(sessionId, UserTokens.of(token));
        delegatedTokens.remove(sessionId);
    }

    /**
     * Registers a user access token you already hold, skipping the consent
     * redirect. Without a refresh token the SDK cannot renew it, so the
     * delegation lasts only as long as the token does.
     */
    public void setUserToken(String sessionId, String accessToken) {
        requireSession(sessionId);
        if (accessToken == null || accessToken.isBlank()) {
            throw new LumoAuthValidationException("an access token is required");
        }
        userTokens.put(sessionId, new UserTokens(accessToken, null, null, List.of()));
        delegatedTokens.remove(sessionId);
    }

    // ── Step 2: token exchange ────────────────────────────────────────

    /**
     * Produces a delegated token for a session, combining the user's token
     * (subject) with the agent's (actor). The result is cached; scopes may only
     * narrow what the user consented to.
     */
    public String exchange(String sessionId, String... scopes) {
        UserTokens user = ensureUserToken(sessionId);
        String agentToken = agent.accessToken();
        TokenResponse response;
        try {
            response = resource.exchange(user.accessToken(), agentToken, scopes);
        } catch (LumoAuthApiException e) {
            throw annotate(e, "token exchange failed");
        }
        delegatedTokens.put(sessionId, response.accessToken());
        return response.accessToken();
    }

    /** The cached delegated token for a session, performing the exchange if there isn't one yet. */
    public String delegatedToken(String sessionId) {
        String token = delegatedTokens.get(sessionId);
        return token != null ? token : exchange(sessionId);
    }

    // ── Step 3: delegated requests ────────────────────────────────────

    /** Makes a request with a session's delegated token and decodes the JSON response (null type to discard). */
    public <T> T request(String sessionId, String method, String path, Object body, Class<T> type) {
        return client.transport().send(method, path, requestWith(body, delegatedToken(sessionId)), type);
    }

    /** {@link #request} without response handling. */
    public HttpResponse<byte[]> requestRaw(String sessionId, String method, String path, Object body) {
        return client.transport().sendRaw(method, path, requestWith(body, delegatedToken(sessionId)));
    }

    // ── Step 4: nested delegation ─────────────────────────────────────

    /**
     * Mints a token for the chain user → this agent → sub-agent. Each hop may
     * only narrow scopes, and LumoAuth caps the chain at
     * {@link DelegationResource#MAX_DELEGATION_DEPTH}. {@code subAgentToken} is
     * the sub-agent's own client-credentials token.
     */
    public String delegateToSubAgent(String sessionId, String subAgentToken, String... scopes) {
        if (subAgentToken == null || subAgentToken.isBlank()) {
            throw new LumoAuthValidationException("the sub-agent's own access token is required");
        }
        String ourToken = delegatedToken(sessionId);
        try {
            return resource.exchange(ourToken, subAgentToken, scopes).accessToken();
        } catch (LumoAuthApiException e) {
            throw annotate(e, "nested delegation failed");
        }
    }

    // ── Introspection ─────────────────────────────────────────────────

    /** The actors recorded in a delegated JWT, outermost first. Decoded without signature verification. */
    public List<String> actorChain(String token) {
        return DelegationResource.parseActorChain(token);
    }

    /** The session IDs holding user tokens. */
    public List<String> activeSessions() {
        return List.copyOf(userTokens.keySet());
    }

    /** Whether a delegated token is cached for a session. */
    public boolean hasDelegation(String sessionId) {
        return delegatedTokens.containsKey(sessionId);
    }

    // ── Step 5: revocation ────────────────────────────────────────────

    /**
     * Ends a delegation: revokes the user's refresh token at the server, which
     * invalidates every derived token, and drops the local state. Local state is
     * cleared even if the server call fails, so a revoked session never keeps
     * serving requests from cache.
     */
    public void revoke(String sessionId) {
        UserTokens user = userTokens.remove(sessionId);
        delegatedTokens.remove(sessionId);
        if (user == null || user.refreshToken() == null || user.refreshToken().isEmpty()) {
            return;
        }
        resource.revoke(RevokeRequest.refreshToken(user.refreshToken(), agent.clientId(), agent.clientSecret()));
    }

    /** Revokes every active session, rethrowing the first failure after attempting the rest. */
    public void revokeAll() {
        LumoAuthException first = null;
        for (String sessionId : activeSessions()) {
            try {
                revoke(sessionId);
            } catch (LumoAuthException e) {
                if (first == null) {
                    first = e;
                }
            }
        }
        if (first != null) {
            throw first;
        }
    }

    // ── Internal ──────────────────────────────────────────────────────

    private UserTokens ensureUserToken(String sessionId) {
        UserTokens user = userTokens.get(sessionId);
        if (user == null) {
            throw new LumoAuthConfigException("no user token for session \"" + sessionId
                + "\" - complete the consent flow (consentUrl → handleConsentCallback) or register one with setUserToken");
        }
        if (!user.expired() || user.refreshToken() == null || user.refreshToken().isEmpty()) {
            // Not expired, or expired with nothing to refresh from: let the server decide.
            return user;
        }
        TokenResponse token = resource.refreshUserToken(
            RefreshTokenRequest.of(user.refreshToken(), agent.clientId(), agent.clientSecret()));
        UserTokens refreshed = UserTokens.of(token);
        if (refreshed.refreshToken() == null || refreshed.refreshToken().isEmpty()) {
            refreshed = new UserTokens(refreshed.accessToken(), user.refreshToken(), refreshed.expiresAt(), refreshed.scopes());
        }
        userTokens.put(sessionId, refreshed);
        delegatedTokens.remove(sessionId); // the derived token is stale now
        return refreshed;
    }

    private static ApiRequest requestWith(Object body, String bearer) {
        ApiRequest request = body == null ? ApiRequest.empty() : ApiRequest.json(body);
        return request.header("Authorization", "Bearer " + bearer);
    }

    private static void requireSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new LumoAuthValidationException("a session ID is required");
        }
    }

    /** Adds delegation context to an exchange failure, naming the depth limit when that is what the server rejected. */
    private static LumoAuthException annotate(LumoAuthApiException e, String prefix) {
        if (e.bodyField("error").map("delegation_depth_exceeded"::equals).orElse(false)) {
            int maxDepth = e.bodyAsMap().map(m -> m.get("max_depth")).filter(Number.class::isInstance)
                .map(n -> ((Number) n).intValue()).orElse(DelegationResource.MAX_DELEGATION_DEPTH);
            return new LumoAuthValidationException("delegation chain too deep (maximum depth: " + maxDepth + ")", e);
        }
        return LumoAuthApiException.of(e.statusCode(), e.code(), prefix + ": " + e.getMessage(), e.body(),
            e instanceof io.lumoauth.errors.LumoAuthRateLimitException r ? r.retryAfter().orElse(null) : null);
    }

    @SuppressWarnings("unused")
    private static List<String> list(String... values) {
        return values == null ? List.of() : Arrays.asList(values);
    }
}
