package io.lumoauth;

/**
 * Supplies the bearer token for a request. It is called once per request, so an
 * implementation can refresh transparently; returning {@code null} or an empty
 * string means "no bearer token", and the client falls back to its API key.
 *
 * <pre>{@code
 * LumoAuth lumo = LumoAuth.builder()
 *     .tokenProvider(() -> tokenCache.currentAccessToken())
 *     .build();
 * }</pre>
 */
@FunctionalInterface
public interface TokenProvider {
    String token();

    /** A provider for a token that never changes. */
    static TokenProvider fixed(String token) {
        return () -> token;
    }
}
