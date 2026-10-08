package io.lumoauth.model;

import io.lumoauth.errors.LumoAuthValidationException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An agent registration.
 *
 * <pre>{@code
 * RegisterAgentRequest.builder("Document Analyser", clientId)
 *     .description("Summarises documents")
 *     .capabilities(List.of("read:documents", "tool:search_web"))
 *     .jwksUri("https://agent.example.com/.well-known/jwks.json")
 *     .build();
 * }</pre>
 *
 * @param name         the human-readable agent name. Required.
 * @param clientId     the OAuth client identifying the agent. Required.
 * @param description  what the agent is for.
 * @param capabilities the slugs the agent declares.
 * @param jwksUri      the agent's public JWKS; required for AAuth and proof-of-possession flows.
 */
public record RegisterAgentRequest(String name, String clientId, String description, List<String> capabilities, String jwksUri) {

    public RegisterAgentRequest {
        capabilities = Models.list(capabilities);
    }

    public static Builder builder(String name, String clientId) {
        return new Builder(name, clientId);
    }

    /** The wire body, validating the required fields. */
    public Map<String, Object> toBody() {
        if (name == null || name.isBlank()) {
            throw new LumoAuthValidationException("name is required to register an agent");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new LumoAuthValidationException("clientId is required to register an agent");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("client_id", clientId);
        if (description != null && !description.isBlank()) {
            body.put("description", description);
        }
        if (!capabilities.isEmpty()) {
            body.put("capabilities", capabilities);
        }
        if (jwksUri != null && !jwksUri.isBlank()) {
            body.put("jwks_uri", jwksUri);
        }
        return body;
    }

    public RegisterAgentRequest withClientId(String newClientId) {
        return new RegisterAgentRequest(name, newClientId, description, capabilities, jwksUri);
    }

    public static final class Builder {
        private final String name;
        private String clientId;
        private String description;
        private List<String> capabilities;
        private String jwksUri;

        private Builder(String name, String clientId) {
            this.name = name;
            this.clientId = clientId;
        }

        public Builder clientId(String value) {
            this.clientId = value;
            return this;
        }

        public Builder description(String value) {
            this.description = value;
            return this;
        }

        public Builder capabilities(List<String> value) {
            this.capabilities = value;
            return this;
        }

        public Builder jwksUri(String value) {
            this.jwksUri = value;
            return this;
        }

        public RegisterAgentRequest build() {
            return new RegisterAgentRequest(name, clientId, description, capabilities, jwksUri);
        }
    }
}
