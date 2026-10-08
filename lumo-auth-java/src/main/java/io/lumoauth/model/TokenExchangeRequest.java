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
public record TokenExchangeRequest(String subjectToken, String actorToken, String audience, List<String> scopes) {

    public TokenExchangeRequest {
        scopes = Models.list(scopes);
    }

    public static TokenExchangeRequest of(String subjectToken) {
        return new TokenExchangeRequest(subjectToken, null, null, null);
    }

    public TokenExchangeRequest actorToken(String value) {
        return new TokenExchangeRequest(subjectToken, value, audience, scopes);
    }

    public TokenExchangeRequest audience(String value) {
        return new TokenExchangeRequest(subjectToken, actorToken, value, scopes);
    }

    public TokenExchangeRequest scopes(List<String> value) {
        return new TokenExchangeRequest(subjectToken, actorToken, audience, value);
    }
}
