package io.lumoauth.aauth;

/**
 * Options for {@link AAuthSigner#signRequest}.
 *
 * @param body          the exact request body being signed; null or empty means no body
 * @param contentType   the media type of the body; defaults to {@code application/json}
 * @param agentToken    the {@code agent+jwt} presented in the Agent-Auth header (travels outside the signature)
 * @param authorization the value of a covered Authorization header, when the request carries one
 * @param signatureKey  the value of a covered Signature-Key header
 * @param created       overrides the signature timestamp (seconds). Testing only.
 * @param nonce         overrides the generated nonce. Testing only.
 */
public record SignOptions(byte[] body, String contentType, String agentToken, String authorization,
                          String signatureKey, long created, String nonce) {

    public static final SignOptions NONE = new SignOptions(null, null, null, null, null, 0, null);

    public static SignOptions body(byte[] body) {
        return new SignOptions(body, null, null, null, null, 0, null);
    }

    public SignOptions contentType(String value) {
        return new SignOptions(body, value, agentToken, authorization, signatureKey, created, nonce);
    }

    public SignOptions agentToken(String value) {
        return new SignOptions(body, contentType, value, authorization, signatureKey, created, nonce);
    }

    public SignOptions authorization(String value) {
        return new SignOptions(body, contentType, agentToken, value, signatureKey, created, nonce);
    }

    public SignOptions signatureKey(String value) {
        return new SignOptions(body, contentType, agentToken, authorization, value, created, nonce);
    }

    public SignOptions created(long value) {
        return new SignOptions(body, contentType, agentToken, authorization, signatureKey, value, nonce);
    }

    public SignOptions nonce(String value) {
        return new SignOptions(body, contentType, agentToken, authorization, signatureKey, created, value);
    }
}
