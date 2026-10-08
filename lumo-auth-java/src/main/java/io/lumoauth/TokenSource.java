package io.lumoauth;

/**
 * The minimal contract the JIT and delegation helpers need: where the
 * instance lives, which org it belongs to, and a bearer token that stays
 * fresh. {@link LumoAgent} satisfies it.
 */
public interface TokenSource {
    String baseUrl();

    String orgId();

    /** A valid access token, authenticating or refreshing as needed. */
    String accessToken();
}
