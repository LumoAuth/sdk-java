package io.lumoauth.model;

import java.util.List;

/**
 * An RFC 8693 token exchange.
 *
 * @param subjectToken the token representing the principal being acted for. Required.
 * @param actorToken   the token of the party doing the acting (the agent); set it to build a delegation chain with an {@code act} claim.
 * @param audience     sent as the RFC 8693 {@code audience} parameter; LumoAuth binds the issued token's {@code aud} from {@code resource}, not from this.
 * @param scopes       optionally narrows the issued token.
 * @param resource     the RFC 8707 resource indicator: the absolute https URL of the API the issued token is for. It becomes
 *                     the token's {@code aud}; without it an agent on-behalf-of token is bound to the acting agent's id.
 */
public record TokenExchangeRequest(String subjectToken, String actorToken, String audience, List<String> scopes,
                                   String subjectTokenType, String actorTokenType, String resource) {

    public TokenExchangeRequest {
        scopes = Models.list(scopes);
    }

    /** The six-argument form, kept for callers that pre-date the resource indicator. */
    public TokenExchangeRequest(String subjectToken, String actorToken, String audience, List<String> scopes,
                                String subjectTokenType, String actorTokenType) {
        this(subjectToken, actorToken, audience, scopes, subjectTokenType, actorTokenType, null);
    }

    /** The four-argument form, kept for callers that pre-date the explicit token types (both default to access tokens). */
    public TokenExchangeRequest(String subjectToken, String actorToken, String audience, List<String> scopes) {
        this(subjectToken, actorToken, audience, scopes, null, null, null);
    }

    public static TokenExchangeRequest of(String subjectToken) {
        return new TokenExchangeRequest(subjectToken, null, null, null, null, null, null);
    }

    public TokenExchangeRequest actorToken(String value) {
        return new TokenExchangeRequest(subjectToken, value, audience, scopes, subjectTokenType, actorTokenType, resource);
    }

    public TokenExchangeRequest audience(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, value, scopes, subjectTokenType, actorTokenType, resource);
    }

    /**
     * Declares what {@code subjectToken} is: one of {@code AuthResource.TOKEN_TYPE_ACCESS_TOKEN} (the default),
     * {@code TOKEN_TYPE_JWT}, {@code TOKEN_TYPE_ID_TOKEN} or {@code TOKEN_TYPE_REFRESH_TOKEN}. The server refuses a
     * token that does not match its declared type (sdk-contract/token-types.json), and never accepts a refresh token
     * as the subject when an agent acts on a user's behalf.
     */
    public TokenExchangeRequest subjectTokenType(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, scopes, value, actorTokenType, resource);
    }

    /** Declares what {@code actorToken} is; defaults to an access token. */
    public TokenExchangeRequest actorTokenType(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, scopes, subjectTokenType, value, resource);
    }

    public TokenExchangeRequest scopes(List<String> value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, value, subjectTokenType, actorTokenType, resource);
    }

    /** Binds the issued token's {@code aud} to the API at this https URL (RFC 8707). */
    public TokenExchangeRequest resource(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, scopes, subjectTokenType, actorTokenType, value);
    }
}
