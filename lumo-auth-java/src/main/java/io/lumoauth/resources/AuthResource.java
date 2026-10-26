package io.lumoauth.resources;

import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.model.AuthorizationUrlRequest;
import io.lumoauth.model.CodeExchangeRequest;
import io.lumoauth.model.Models;
import io.lumoauth.model.RefreshTokenRequest;
import io.lumoauth.model.RevokeRequest;
import io.lumoauth.model.TokenExchangeRequest;
import io.lumoauth.model.TokenResponse;
import io.lumoauth.model.UserInfo;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The org-scoped OAuth 2.1 endpoints: authorize, token, userinfo, revoke.
 * Token-endpoint grants authenticate through the form body and never carry the
 * client's default credential.
 */
public final class AuthResource {

    public static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    /** RFC 8693 token type: an opaque or at+jwt access token issued by the organization (the default). */
    public static final String TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    /** RFC 8693 token type: an at+jwt access token, or an external workload identity token presented by a registered agent. */
    public static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";
    /** RFC 8693 token type: an OpenID Connect ID token issued by the organization to the exchanging client. */
    public static final String TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    /**
     * RFC 8693 token type: a refresh token issued to the exchanging client. Refused as the subject when an agent acts
     * on a user's behalf (the actor token is an agent access token): 400 invalid_request.
     */
    public static final String TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token";

    private final HttpTransport http;

    public AuthResource(HttpTransport http) {
        this.http = http;
    }

    /** The URL to redirect a user to in order to start the authorization-code flow. */
    public String authorizationUrl(AuthorizationUrlRequest params) {
        if (isBlank(params.clientId())) {
            throw new LumoAuthValidationException("clientId is required to build an authorization URL");
        }
        if (isBlank(params.redirectUri())) {
            throw new LumoAuthValidationException("redirectUri is required to build an authorization URL");
        }
        Routes.Route route = http.resolve(Routes.OAUTH_AUTHORIZE, null);
        Map<String, String> query = new LinkedHashMap<>();
        query.put("response_type", isBlank(params.responseType()) ? "code" : params.responseType());
        query.put("client_id", params.clientId());
        query.put("redirect_uri", params.redirectUri());
        query.put("scope", isBlank(params.scope()) ? AuthorizationUrlRequest.DEFAULT_SCOPE : params.scope());
        if (!isBlank(params.state())) {
            query.put("state", params.state());
        }
        if (!isBlank(params.codeChallenge())) {
            query.put("code_challenge", params.codeChallenge());
            query.put("code_challenge_method", isBlank(params.codeChallengeMethod()) ? "S256" : params.codeChallengeMethod());
        }
        if (!isBlank(params.prompt())) {
            query.put("prompt", params.prompt());
        }
        if (!isBlank(params.accessType())) {
            query.put("access_type", params.accessType());
        }
        query.putAll(params.extra());
        return http.baseUrl() + route.path() + "?" + HttpTransport.formEncode(query);
    }

    /** Trades an authorization code for tokens. */
    public TokenResponse exchangeCode(CodeExchangeRequest params) {
        if (isBlank(params.code())) {
            throw new LumoAuthValidationException("code is required to exchange an authorization code");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", params.code());
        form.put("redirect_uri", params.redirectUri());
        form.put("client_id", params.clientId());
        putIfPresent(form, "client_secret", params.clientSecret());
        putIfPresent(form, "code_verifier", params.codeVerifier());
        return tokenRequest(form);
    }

    /** Exchanges a refresh token for a new access token. */
    public TokenResponse refreshToken(RefreshTokenRequest params) {
        if (isBlank(params.refreshToken())) {
            throw new LumoAuthValidationException("refreshToken is required");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", params.refreshToken());
        form.put("client_id", params.clientId());
        putIfPresent(form, "client_secret", params.clientSecret());
        if (!params.scopes().isEmpty()) {
            form.put("scope", Models.joinScopes(params.scopes()));
        }
        return tokenRequest(form);
    }

    /** The machine-to-machine client-credentials grant. No scopes means the client's defaults. */
    public TokenResponse clientCredentials(String clientId, String clientSecret, String... scopes) {
        return clientCredentials(clientId, clientSecret, scopes == null ? List.of() : Arrays.asList(scopes));
    }

    public TokenResponse clientCredentials(String clientId, String clientSecret, List<String> scopes) {
        if (isBlank(clientId) || isBlank(clientSecret)) {
            throw new LumoAuthValidationException(
                "clientId and clientSecret are both required for the client-credentials grant");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "client_credentials");
        form.put("client_id", clientId);
        form.put("client_secret", clientSecret);
        if (scopes != null && !scopes.isEmpty()) {
            form.put("scope", Models.joinScopes(scopes));
        }
        return tokenRequest(form);
    }

    /**
     * An RFC 8693 exchange: the primitive behind delegation and MCP audience scoping. The subject must
     * still be an active principal: a deactivated or blocked user, or a suspended agent, gets
     * {@code invalid_grant}. A JIT task token is never accepted as the subject.
     */
    public TokenResponse tokenExchange(TokenExchangeRequest params) {
        if (isBlank(params.subjectToken())) {
            throw new LumoAuthValidationException("subjectToken is required for a token exchange");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
        form.put("subject_token", params.subjectToken());
        form.put("subject_token_type", isBlank(params.subjectTokenType()) ? TOKEN_TYPE_ACCESS_TOKEN : params.subjectTokenType());
        if (!isBlank(params.actorToken())) {
            form.put("actor_token", params.actorToken());
            form.put("actor_token_type", isBlank(params.actorTokenType()) ? TOKEN_TYPE_ACCESS_TOKEN : params.actorTokenType());
        }
        putIfPresent(form, "audience", params.audience());
        putIfPresent(form, "resource", params.resource());
        if (!params.scopes().isEmpty()) {
            form.put("scope", Models.joinScopes(params.scopes()));
        }
        return tokenRequest(form);
    }

    /** Invalidates an access or refresh token. Revoking a refresh token also invalidates the tokens derived from it. */
    public void revoke(RevokeRequest params) {
        if (isBlank(params.token())) {
            throw new LumoAuthValidationException("token is required to revoke");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", params.token());
        putIfPresent(form, "token_type_hint", params.tokenTypeHint());
        putIfPresent(form, "client_id", params.clientId());
        putIfPresent(form, "client_secret", params.clientSecret());
        // The revocation endpoint authenticates through the form body.
        http.callNode(Routes.OAUTH_REVOKE, null, ApiRequest.empty().withForm(form).noAuth());
    }

    /** The OIDC UserInfo claims for the client's own credential. */
    public UserInfo userinfo() {
        return userinfo(null);
    }

    /** The OIDC UserInfo claims for an access token (null for the client's own credential). */
    public UserInfo userinfo(String accessToken) {
        ApiRequest request = ApiRequest.empty();
        if (!isBlank(accessToken)) {
            request.header("Authorization", "Bearer " + accessToken);
        }
        return http.call(Routes.OAUTH_USERINFO, null, request, UserInfo.class);
    }

    private TokenResponse tokenRequest(Map<String, String> form) {
        TokenResponse token = http.call(Routes.OAUTH_TOKEN, null, ApiRequest.empty().withForm(form).noAuth(), TokenResponse.class);
        if (token == null || isBlank(token.accessToken())) {
            throw new LumoAuthValidationException("the token endpoint returned no access_token");
        }
        return token;
    }

    private static void putIfPresent(Map<String, String> form, String key, String value) {
        if (!isBlank(value)) {
            form.put(key, value);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
