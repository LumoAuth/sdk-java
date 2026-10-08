package io.lumoauth.errors;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * Thrown when the server answers with a non-2xx status. {@link #statusCode()} is
 * the HTTP status, {@link #body()} the decoded response body (a {@code Map} for JSON
 * objects, a {@code String} otherwise, {@code null} when empty).
 *
 * <p>The four common statuses have their own subclasses; use {@link #of} to build
 * the right one from a response.
 */
public class LumoAuthApiException extends LumoAuthException {

    private final int statusCode;
    private final transient Object body;

    public LumoAuthApiException(int statusCode, String code, String message, Object body) {
        this(statusCode, code, message, body, null);
    }

    protected LumoAuthApiException(int statusCode, String code, String message, Object body, Throwable cause) {
        super(code == null || code.isEmpty() ? ErrorCodes.forStatus(statusCode) : code, message, cause);
        this.statusCode = statusCode;
        this.body = body;
    }

    /** Builds the subclass matching the status (401, 403, 404, 429) or a plain API exception. */
    public static LumoAuthApiException of(int statusCode, String code, String message, Object body, Duration retryAfter) {
        return switch (statusCode) {
            case 401 -> new LumoAuthAuthenticationException(statusCode, code, message, body);
            case 403 -> new LumoAuthPermissionDeniedException(statusCode, code, message, body);
            case 404 -> new LumoAuthNotFoundException(statusCode, code, message, body);
            case 429 -> new LumoAuthRateLimitException(statusCode, code, message, body, retryAfter);
            default -> new LumoAuthApiException(statusCode, code, message, body);
        };
    }

    /** The HTTP status of the response, or 0 when the exception was raised locally. */
    public int statusCode() {
        return statusCode;
    }

    /** The decoded response body: a Map for JSON objects, a String otherwise, null when empty. */
    public Object body() {
        return body;
    }

    /** The response body as a map when it was a JSON object; empty otherwise. */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> bodyAsMap() {
        if (body instanceof Map<?, ?> map) {
            return Optional.of(Collections.unmodifiableMap((Map<String, Object>) map));
        }
        return Optional.empty();
    }

    /** One string field of a JSON error body, when present. */
    public Optional<String> bodyField(String key) {
        return bodyAsMap().map(m -> m.get(key)).filter(String.class::isInstance).map(String.class::cast);
    }
}
