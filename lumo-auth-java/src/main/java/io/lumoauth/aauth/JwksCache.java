package io.lumoauth.aauth;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;

/**
 * Caches an issuer's JWKS for a TTL, so a busy resource server verifies
 * tokens without fetching keys on every request. Thread-safe.
 */
public final class JwksCache {

    private final String issuer;
    private final Duration ttl;
    private final HttpClient httpClient;
    private Jwks keys;
    private Instant expiresAt = Instant.EPOCH;

    /** A cache for one issuer; a null or non-positive TTL means one hour. */
    public JwksCache(String issuer, Duration ttl, HttpClient httpClient) {
        this.issuer = issuer;
        this.ttl = ttl == null || ttl.isZero() || ttl.isNegative() ? Duration.ofHours(1) : ttl;
        this.httpClient = httpClient;
    }

    public JwksCache(String issuer) {
        this(issuer, null, null);
    }

    /** The cached key set, fetched when absent or stale. */
    public Jwks get() {
        synchronized (this) {
            if (keys != null && Instant.now().isBefore(expiresAt)) {
                return keys;
            }
        }
        Jwks fresh = AAuthVerifier.fetchIssuerJwks(issuer, httpClient);
        synchronized (this) {
            keys = fresh;
            expiresAt = Instant.now().plus(ttl);
        }
        return fresh;
    }

    /** Drops the cached keys, forcing the next {@link #get} to refetch. Call it when verification fails on an unknown kid. */
    public synchronized void invalidate() {
        keys = null;
        expiresAt = Instant.EPOCH;
    }

    /** Verify options for this issuer that use the cached keys. */
    public VerifyOptions verifyOptions(String resource) {
        return VerifyOptions.of(issuer, resource).jwks(get()).httpClient(httpClient);
    }
}
