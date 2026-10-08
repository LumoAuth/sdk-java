package io.lumoauth.aauth;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** A protected resource server's AAuth discovery document. */
public record AAuthResourceMetadata(
    @JsonProperty("resource") String resource,
    @JsonProperty("jwks_uri") String jwksUri,
    @JsonProperty("resource_token_endpoint") String resourceTokenEndpoint,
    @JsonProperty("supported_scopes") List<String> supportedScopes
) {
    public AAuthResourceMetadata {
        supportedScopes = supportedScopes == null ? List.of() : List.copyOf(supportedScopes);
    }
}
