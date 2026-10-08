package io.lumoauth.errors;

import java.time.Duration;
import java.util.Optional;

/** HTTP 429. {@link #retryAfter()} carries the server's Retry-After hint when it sent one. */
public class LumoAuthRateLimitException extends LumoAuthApiException {

    private final Duration retryAfter;

    public LumoAuthRateLimitException(int statusCode, String code, String message, Object body, Duration retryAfter) {
        super(statusCode, code, message, body);
        this.retryAfter = retryAfter;
    }

    /** How long the server asked the client to wait, when it said. */
    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }
}
