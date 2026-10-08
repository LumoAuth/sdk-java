package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Optional;

/** An OAuth 2.1 token endpoint response. */
public record TokenResponse(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("refresh_token") String refreshToken,
    @JsonProperty("id_token") String idToken,
    @JsonProperty("token_type") String tokenType,
    @JsonProperty("expires_in") int expiresIn,
    @JsonProperty("scope") String scope,
    @JsonProperty("issued_token_type") String issuedTokenType
) {
    /** The granted scopes, split on whitespace. */
    public List<String> scopes() {
        return Models.splitScopes(scope);
    }

    public Optional<String> refreshTokenOpt() {
        return Optional.ofNullable(Models.blankToNull(refreshToken));
    }

    public Optional<String> idTokenOpt() {
        return Optional.ofNullable(Models.blankToNull(idToken));
    }
}
