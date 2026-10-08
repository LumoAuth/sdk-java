package io.lumoauth.web;

import io.lumoauth.LumoAuth;
import io.lumoauth.errors.LumoAuthAuthenticationException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.model.AuthorizationUrlRequest;
import io.lumoauth.model.CodeExchangeRequest;
import io.lumoauth.model.RefreshTokenRequest;
import io.lumoauth.model.RevokeRequest;
import io.lumoauth.model.TokenResponse;
import io.lumoauth.model.UserInfo;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * The OAuth 2.1 Authorization Code + PKCE flow as framework-neutral steps, for
 * web apps that are not on Spring (the Spring Boot starter wires Spring
 * Security's own OIDC login instead).
 *
 * <pre>{@code
 * AuthorizationCodeFlow flow = AuthorizationCodeFlow.builder(lumo, clientId, "https://app.example.com/auth/callback")
 *     .clientSecret(clientSecret).build();
 *
 * // GET /auth/login
 * PendingLogin login = flow.start("/dashboard");
 * session.put("lumo_login", login);          // keep it server-side
 * response.redirect(login.authorizationUrl());
 *
 * // GET /auth/callback?code=...&state=...
 * SignedIn user = flow.complete(session.get("lumo_login"), request.queryParams());
 * session.put("lumo_user", user);
 * response.redirect(login.returnTo());
 * }</pre>
 */
public final class AuthorizationCodeFlow {

    /** The per-login state carried across the redirect. Store it server-side; it holds the PKCE verifier. */
    public record PendingLogin(String state, String codeVerifier, String redirectUri, String returnTo, String authorizationUrl) {
    }

    /** A signed-in user: their UserInfo claims and the tokens issued for them. */
    public record SignedIn(UserInfo user, TokenResponse tokens, Instant expiresAt) {
        public boolean expired() {
            return expiresAt != null && Instant.now().isAfter(expiresAt);
        }
    }

    private final LumoAuth lumo;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String scope;

    private AuthorizationCodeFlow(Builder b) {
        if (b.lumo == null) {
            throw new LumoAuthConfigException("a LumoAuth client is required");
        }
        if (b.clientId == null || b.clientId.isBlank()) {
            throw new LumoAuthConfigException("clientId is required");
        }
        if (b.redirectUri == null || b.redirectUri.isBlank()) {
            throw new LumoAuthConfigException("redirectUri is required and must match a redirect URI registered on the OAuth client");
        }
        this.lumo = b.lumo;
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret;
        this.redirectUri = b.redirectUri;
        this.scope = b.scope == null || b.scope.isBlank() ? AuthorizationUrlRequest.DEFAULT_SCOPE : b.scope;
    }

    public static Builder builder(LumoAuth lumo, String clientId, String redirectUri) {
        return new Builder(lumo, clientId, redirectUri);
    }

    /** Starts a login: generates PKCE and state and builds the authorization URL. {@code returnTo} is sanitised against open redirects. */
    public PendingLogin start(String returnTo) {
        Pkce.Pair pkce = Pkce.generate();
        String state = Pkce.randomToken(32);
        String url = lumo.auth().authorizationUrl(AuthorizationUrlRequest.builder(clientId, redirectUri)
            .scope(scope)
            .state(state)
            .codeChallenge(pkce.challenge())
            .build());
        return new PendingLogin(state, pkce.verifier(), redirectUri, sanitizeReturnTo(returnTo, "/"), url);
    }

    public PendingLogin start() {
        return start(null);
    }

    /**
     * Completes a login from the callback's query parameters: checks the error
     * and state parameters, exchanges the code, and fetches the user's claims.
     *
     * @throws LumoAuthAuthenticationException when the provider reported an error or the state does not match
     */
    public SignedIn complete(PendingLogin pending, Map<String, String> callbackParams) {
        if (pending == null) {
            throw new LumoAuthAuthenticationException(0, null, "no login in progress", null);
        }
        String error = callbackParams.get("error");
        if (error != null && !error.isBlank()) {
            String description = callbackParams.getOrDefault("error_description", "");
            throw new LumoAuthAuthenticationException(0, error, error + (description.isEmpty() ? "" : ": " + description), null);
        }
        String code = callbackParams.get("code");
        String state = callbackParams.get("state");
        if (code == null || code.isBlank() || state == null || state.isBlank()) {
            throw new LumoAuthValidationException("missing code or state");
        }
        if (!state.equals(pending.state())) {
            throw new LumoAuthAuthenticationException(0, null, "CSRF state mismatch", null);
        }
        TokenResponse tokens = lumo.auth().exchangeCode(CodeExchangeRequest.of(code, pending.redirectUri(), clientId)
            .clientSecret(clientSecret)
            .codeVerifier(pending.codeVerifier()));
        UserInfo user = lumo.auth().userinfo(tokens.accessToken());
        return new SignedIn(user, tokens, expiry(tokens));
    }

    /** Renews an expired session's access token with its refresh token; empty when there is nothing to refresh. */
    public Optional<SignedIn> refresh(SignedIn session) {
        if (session == null || session.tokens().refreshToken() == null || session.tokens().refreshToken().isEmpty()) {
            return Optional.empty();
        }
        TokenResponse refreshed = lumo.auth().refreshToken(
            RefreshTokenRequest.of(session.tokens().refreshToken(), clientId, clientSecret));
        if (refreshed.refreshToken() == null || refreshed.refreshToken().isEmpty()) {
            refreshed = new TokenResponse(refreshed.accessToken(), session.tokens().refreshToken(), refreshed.idToken(),
                refreshed.tokenType(), refreshed.expiresIn(), refreshed.scope(), refreshed.issuedTokenType());
        }
        return Optional.of(new SignedIn(session.user(), refreshed, expiry(refreshed)));
    }

    /** Best-effort server-side revocation of a session's refresh token, for sign-out. Never throws. */
    public void revoke(SignedIn session) {
        if (session == null || session.tokens().refreshToken() == null || session.tokens().refreshToken().isEmpty()) {
            return;
        }
        try {
            lumo.auth().revoke(RevokeRequest.refreshToken(session.tokens().refreshToken(), clientId, clientSecret));
        } catch (RuntimeException ignored) {
            // A failure here must not strand the user in a session they asked to end.
        }
    }

    /** A client authenticated as the signed-in user, so authorization checks run under their identity. */
    public LumoAuth clientFor(SignedIn session) {
        return LumoAuth.builder()
            .baseUrl(lumo.baseUrl())
            .orgId(lumo.orgId().orElse(null))
            .apiKey(null)
            .accessToken(session.tokens().accessToken())
            .httpClient(lumo.transport().httpClient())
            .timeout(lumo.transport().timeout())
            .build();
    }

    /** Blocks open redirects through a return-to parameter: only same-origin absolute paths pass. */
    public static String sanitizeReturnTo(String value, String fallback) {
        if (value == null || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) {
            return fallback;
        }
        return value;
    }

    private static Instant expiry(TokenResponse tokens) {
        return tokens.expiresIn() > 0 ? Instant.now().plusSeconds(tokens.expiresIn()) : null;
    }

    public static final class Builder {
        private final LumoAuth lumo;
        private final String clientId;
        private final String redirectUri;
        private String clientSecret;
        private String scope;

        private Builder(LumoAuth lumo, String clientId, String redirectUri) {
            this.lumo = lumo;
            this.clientId = clientId;
            this.redirectUri = redirectUri;
        }

        /** Required for confidential clients; omit for public ones, which rely on PKCE alone. */
        public Builder clientSecret(String value) {
            this.clientSecret = value;
            return this;
        }

        /** Defaults to {@code openid profile email}. */
        public Builder scope(String value) {
            this.scope = value;
            return this;
        }

        public AuthorizationCodeFlow build() {
            return new AuthorizationCodeFlow(this);
        }
    }
}
