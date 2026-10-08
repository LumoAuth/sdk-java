package io.lumoauth.aauth;

import java.util.Optional;

/**
 * A successful response from the agent token endpoint. When the server
 * requires user consent instead, {@link #authorizationRequired()} is true and
 * the token fields are null.
 *
 * @param requestType           the flow: auth, code, exchange, or refresh
 * @param authToken             the {@code auth+jwt} to present to the resource
 * @param expiresIn             the token's lifetime in seconds
 * @param tokenType             normally "auth+jwt"
 * @param refreshToken          present when the grant includes one
 * @param authorizationRequired a human must consent first
 * @param requestToken          identifies the pending request (600s TTL)
 * @param authorizationUri      the consent page to redirect the user to
 */
public record AAuthTokenResponse(String requestType, String authToken, int expiresIn, String tokenType,
                                 String refreshToken, boolean authorizationRequired, String requestToken,
                                 String authorizationUri) {

    static AAuthTokenResponse consent(String requestToken, String authorizationUri, int expiresIn) {
        return new AAuthTokenResponse(null, null, expiresIn, null, null, true, requestToken, authorizationUri);
    }

    public Optional<String> refreshTokenOpt() {
        return Optional.ofNullable(refreshToken).filter(s -> !s.isEmpty());
    }
}
