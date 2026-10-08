package io.lumoauth.model;

/**
 * A token revocation.
 *
 * @param token         the access or refresh token to revoke. Required.
 * @param tokenTypeHint "access_token" or "refresh_token".
 * @param clientId      authenticates the revocation together with the secret.
 * @param clientSecret  the client secret.
 */
public record RevokeRequest(String token, String tokenTypeHint, String clientId, String clientSecret) {

    public static final String HINT_ACCESS_TOKEN = "access_token";
    public static final String HINT_REFRESH_TOKEN = "refresh_token";

    public static RevokeRequest of(String token) {
        return new RevokeRequest(token, null, null, null);
    }

    public static RevokeRequest refreshToken(String token, String clientId, String clientSecret) {
        return new RevokeRequest(token, HINT_REFRESH_TOKEN, clientId, clientSecret);
    }

    public RevokeRequest hint(String value) {
        return new RevokeRequest(token, value, clientId, clientSecret);
    }

    public RevokeRequest client(String id, String secret) {
        return new RevokeRequest(token, tokenTypeHint, id, secret);
    }
}
