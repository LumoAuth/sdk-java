package io.lumoauth.resources;

import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.Json;
import io.lumoauth.model.AuthorizationUrlRequest;
import io.lumoauth.model.CodeExchangeRequest;
import io.lumoauth.model.ConsentUrlRequest;
import io.lumoauth.model.Models;
import io.lumoauth.model.RefreshTokenRequest;
import io.lumoauth.model.RevokeRequest;
import io.lumoauth.model.TokenExchangeRequest;
import io.lumoauth.model.TokenResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The RFC 8693 delegation primitives: the raw operations behind the Chain of
 * Agency. For session-tracked delegation with consent handling and refresh use
 * {@link io.lumoauth.DelegationChain}, which wraps this.
 */
public final class DelegationResource {

    /** The deepest delegation chain LumoAuth will issue tokens for (user → agent → sub-agent). */
    public static final int MAX_DELEGATION_DEPTH = 3;

    private final AuthResource auth;

    public DelegationResource(AuthResource auth) {
        this.auth = auth;
    }

    /** The URL where a user grants an agent delegated access. Requests offline access so the agent receives a refresh token. */
    public String consentUrl(ConsentUrlRequest params) {
        return auth.authorizationUrl(AuthorizationUrlRequest.builder(params.clientId(), params.redirectUri())
            .scope(Models.joinScopes(params.scopes()))
            .state(params.state())
            .prompt("consent")
            .accessType("offline")
            .build());
    }

    /** Trades a consent callback code for the user's tokens. */
    public TokenResponse exchangeCode(CodeExchangeRequest params) {
        return auth.exchangeCode(params);
    }

    /** Refreshes a user's delegated access token. */
    public TokenResponse refreshUserToken(RefreshTokenRequest params) {
        return auth.refreshToken(params);
    }

    /**
     * Combines a subject token (the user) with an actor token (the agent) into a
     * delegated token whose {@code act} claim records the chain. The token is bound
     * to the acting agent; use {@link #exchangeForResource} to bind it to the API it
     * will be sent to.
     */
    public TokenResponse exchange(String subjectToken, String actorToken, String... scopes) {
        return exchange(subjectToken, actorToken, scopes == null ? List.of() : Arrays.asList(scopes));
    }

    public TokenResponse exchange(String subjectToken, String actorToken, List<String> scopes) {
        return exchangeForResource(subjectToken, actorToken, null, scopes);
    }

    /**
     * {@link #exchange} with an RFC 8707 resource indicator: the https URL in {@code resource}
     * becomes the delegated token's {@code aud}.
     */
    public TokenResponse exchangeForResource(String subjectToken, String actorToken, String resource, List<String> scopes) {
        if (subjectToken == null || subjectToken.isBlank()) {
            throw new LumoAuthValidationException("a subject token is required");
        }
        if (actorToken == null || actorToken.isBlank()) {
            throw new LumoAuthValidationException("an actor token is required");
        }
        return auth.tokenExchange(
            TokenExchangeRequest.of(subjectToken).actorToken(actorToken).scopes(scopes).resource(resource));
    }

    /** Invalidates a delegation's refresh token, and with it every token derived from it. */
    public void revoke(RevokeRequest params) {
        RevokeRequest request = params.tokenTypeHint() == null ? params.hint(RevokeRequest.HINT_REFRESH_TOKEN) : params;
        auth.revoke(request);
    }

    /**
     * The {@code sub} of each nested {@code act} claim in a delegated JWT, outermost
     * first. Decoded WITHOUT signature verification: display and audit only.
     */
    public static List<String> parseActorChain(String token) {
        Map<String, Object> claims = decodeJwtPayload(token);
        List<String> actors = new ArrayList<>();
        Object act = claims.get("act");
        while (act instanceof Map<?, ?> map) {
            if (map.get("sub") instanceof String sub && !sub.isEmpty()) {
                actors.add(sub);
            }
            act = map.get("act");
        }
        return List.copyOf(actors);
    }

    /** A JWT's {@code sub} claim. Decoded WITHOUT signature verification: display and audit only. */
    public static Optional<String> tokenSubject(String token) {
        Object sub = decodeJwtPayload(token).get("sub");
        return sub instanceof String s && !s.isEmpty() ? Optional.of(s) : Optional.empty();
    }

    /** Base64url-decodes a JWT's claims segment WITHOUT verifying the signature. */
    public static Map<String, Object> decodeJwtPayload(String token) {
        if (token == null) {
            throw new LumoAuthValidationException("not a JWT: expected at least two dot-separated segments");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length < 2) {
            throw new LumoAuthValidationException("not a JWT: expected at least two dot-separated segments");
        }
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(parts[1].replaceAll("=+$", ""));
        } catch (IllegalArgumentException e) {
            throw new LumoAuthValidationException("could not base64url-decode the JWT payload: " + e.getMessage(), e);
        }
        return Json.toMap(Json.parse(decoded, "JWT payload"));
    }
}
