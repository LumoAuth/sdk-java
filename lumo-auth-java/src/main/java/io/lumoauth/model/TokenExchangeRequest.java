package io.lumoauth.model;

import java.util.List;

/**
 * An RFC 8693 token exchange.
 *
 * @param subjectToken the token representing the principal being acted for. Required.
 * @param actorToken   the token of the party doing the acting (the agent); set it to build a delegation chain with an {@code act} claim.
 * @param audience     scopes the issued token to one resource (an MCP server id, for instance).
 * @param scopes       optionally narrows the issued token.
 */
public record TokenExchangeRequest(String subjectToken, String actorToken, String audience, List<String> scopes,
                                   String subjectTokenType, String actorTokenType) {

    public TokenExchangeRequest {
        scopes = Models.list(scopes);
    }

    /** The four-argument form, kept for callers that pre-date the explicit token types (both default to access tokens). */
    public TokenExchangeRequest(String subjectToken, String actorToken, String audience, List<String> scopes) {
        this(subjectToken, actorToken, audience, scopes, null, null);
    }

    public static TokenExchangeRequest of(String subjectToken) {
        return new TokenExchangeRequest(subjectToken, null, null, null, null, null);
    }

    public TokenExchangeRequest actorToken(String value) {
        return new TokenExchangeRequest(subjectToken, value, audience, scopes, subjectTokenType, actorTokenType);
    }

    public TokenExchangeRequest audience(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, value, scopes, subjectTokenType, actorTokenType);
    }

    /**
     * Declares what {@code subjectToken} is: one of {@code AuthResource.TOKEN_TYPE_ACCESS_TOKEN} (the default),
     * {@code TOKEN_TYPE_JWT}, {@code TOKEN_TYPE_ID_TOKEN} or {@code TOKEN_TYPE_REFRESH_TOKEN}. The server refuses a
     * token that does not match its declared type (sdk-contract/token-types.json).
     */
    public TokenExchangeRequest subjectTokenType(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, scopes, value, actorTokenType);
    }

    /** Declares what {@code actorToken} is; defaults to an access token. */
    public TokenExchangeRequest actorTokenType(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, scopes, subjectTokenType, value);
    }

    public TokenExchangeRequest scopes(List<String> value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, value, subjectTokenType, actorTokenType);
    }
}
