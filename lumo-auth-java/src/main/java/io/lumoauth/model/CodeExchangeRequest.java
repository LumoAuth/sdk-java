package io.lumoauth.model;

/**
 * An authorization-code exchange.
 *
 * @param code         the authorization code from the callback. Required.
 * @param redirectUri  must match the one used to obtain the code. Required.
 * @param clientId     the OAuth client. Required.
 * @param clientSecret required for confidential clients.
 * @param codeVerifier the PKCE verifier matching the challenge sent to the authorization endpoint.
 */
public record CodeExchangeRequest(String code, String redirectUri, String clientId, String clientSecret, String codeVerifier) {

    public static CodeExchangeRequest of(String code, String redirectUri, String clientId) {
        return new CodeExchangeRequest(code, redirectUri, clientId, null, null);
    }

    public CodeExchangeRequest clientSecret(String value) {
        return new CodeExchangeRequest(code, redirectUri, clientId, value, codeVerifier);
    }

    public CodeExchangeRequest codeVerifier(String value) {
        return new CodeExchangeRequest(code, redirectUri, clientId, clientSecret, value);
    }
}
