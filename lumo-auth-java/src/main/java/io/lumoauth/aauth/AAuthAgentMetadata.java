package io.lumoauth.aauth;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** A registered agent's discovery document. */
public record AAuthAgentMetadata(
    @JsonProperty("agent") String agent,
    @JsonProperty("jwks_uri") String jwksUri,
    @JsonProperty("redirect_uris") List<String> redirectUris,
    @JsonProperty("name") String name
) {
    public AAuthAgentMetadata {
        redirectUris = redirectUris == null ? List.of() : List.copyOf(redirectUris);
    }
}
