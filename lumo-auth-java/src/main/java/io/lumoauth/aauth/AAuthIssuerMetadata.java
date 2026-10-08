package io.lumoauth.aauth;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** An AAuth authorization server's discovery document. */
public record AAuthIssuerMetadata(
    @JsonProperty("issuer") String issuer,
    @JsonProperty("aauth_version") String aauthVersion,
    @JsonProperty("jwks_uri") String jwksUri,
    @JsonProperty("agent_token_endpoint") String agentTokenEndpoint,
    @JsonProperty("agent_auth_endpoint") String agentAuthEndpoint,
    @JsonProperty("agent_signing_algs_supported") List<String> agentSigningAlgsSupported,
    @JsonProperty("token_signing_algs_supported") List<String> tokenSigningAlgsSupported,
    @JsonProperty("request_types_supported") List<String> requestTypesSupported,
    @JsonProperty("scopes_supported") List<String> scopesSupported
) {
    public AAuthIssuerMetadata {
        agentSigningAlgsSupported = agentSigningAlgsSupported == null ? List.of() : List.copyOf(agentSigningAlgsSupported);
        tokenSigningAlgsSupported = tokenSigningAlgsSupported == null ? List.of() : List.copyOf(tokenSigningAlgsSupported);
        requestTypesSupported = requestTypesSupported == null ? List.of() : List.copyOf(requestTypesSupported);
        scopesSupported = scopesSupported == null ? List.of() : List.copyOf(scopesSupported);
    }
}
