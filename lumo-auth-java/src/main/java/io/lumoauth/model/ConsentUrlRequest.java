package io.lumoauth.model;

import java.util.List;

/**
 * The consent redirect a user follows to let an agent act on their behalf.
 *
 * @param clientId    the agent's OAuth client. Required.
 * @param redirectUri where consent returns the user. Required.
 * @param scopes      the permissions being requested; defaults to ["read:documents"].
 * @param state       the CSRF token echoed back to the redirect URI.
 */
public record ConsentUrlRequest(String clientId, String redirectUri, List<String> scopes, String state) {

    public static final List<String> DEFAULT_SCOPES = List.of("read:documents");

    public ConsentUrlRequest {
        scopes = scopes == null || scopes.isEmpty() ? DEFAULT_SCOPES : Models.list(scopes);
    }

    public static ConsentUrlRequest of(String clientId, String redirectUri) {
        return new ConsentUrlRequest(clientId, redirectUri, null, null);
    }

    public ConsentUrlRequest scopes(List<String> value) {
        return new ConsentUrlRequest(clientId, redirectUri, value, state);
    }

    public ConsentUrlRequest state(String value) {
        return new ConsentUrlRequest(clientId, redirectUri, scopes, value);
    }
}
