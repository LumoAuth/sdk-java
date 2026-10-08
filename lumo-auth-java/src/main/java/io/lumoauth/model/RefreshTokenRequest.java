package io.lumoauth.model;

import java.util.List;

/**
 * A refresh-token grant.
 *
 * @param refreshToken the token to redeem. Required.
 * @param clientId     the OAuth client. Required.
 * @param clientSecret required for confidential clients.
 * @param scopes       optionally narrows the refreshed token; must be a subset of the original grant.
 */
public record RefreshTokenRequest(String refreshToken, String clientId, String clientSecret, List<String> scopes) {

    public RefreshTokenRequest {
        scopes = Models.list(scopes);
    }

    public static RefreshTokenRequest of(String refreshToken, String clientId, String clientSecret) {
        return new RefreshTokenRequest(refreshToken, clientId, clientSecret, null);
    }

    public RefreshTokenRequest scopes(List<String> value) {
        return new RefreshTokenRequest(refreshToken, clientId, clientSecret, value);
    }
}
