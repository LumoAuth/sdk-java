package io.lumoauth.aauth;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Options for {@link AAuthVerifier#verifyAuthToken}.
 *
 * @param issuer     the trusted issuer URL, e.g. {@code https://app.lumoauth.dev/orgs/acme-corp/api/v1}. Required.
 * @param resource   your resource identifier; it must equal the token's audience. Required.
 * @param jwks       the issuer's keys, supplied directly to skip the fetch (use a {@link JwksCache} on a hot path)
 * @param httpClient fetches the JWKS; defaults to a 30s-timeout client
 * @param clockSkew  tolerance on the expiry check; default zero, like the server
 */
public record VerifyOptions(String issuer, String resource, Jwks jwks, HttpClient httpClient, Duration clockSkew) {

    public static VerifyOptions of(String issuer, String resource) {
        return new VerifyOptions(issuer, resource, null, null, Duration.ZERO);
    }

    public VerifyOptions jwks(Jwks value) {
        return new VerifyOptions(issuer, resource, value, httpClient, clockSkew);
    }

    public VerifyOptions httpClient(HttpClient value) {
        return new VerifyOptions(issuer, resource, jwks, value, clockSkew);
    }

    public VerifyOptions clockSkew(Duration value) {
        return new VerifyOptions(issuer, resource, jwks, httpClient, value);
    }
}
