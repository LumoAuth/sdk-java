package io.lumoauth.errors;

import java.util.List;

/**
 * Client-side validation failed: a required argument is missing or malformed, or
 * the server returned a response whose shape the SDK cannot use.
 */
public class LumoAuthValidationException extends LumoAuthException {

    private final transient List<Object> issues;

    public LumoAuthValidationException(String message) {
        this(message, List.of(), null);
    }

    public LumoAuthValidationException(String message, Throwable cause) {
        this(message, List.of(), cause);
    }

    public LumoAuthValidationException(String message, List<Object> issues, Throwable cause) {
        super(ErrorCodes.VALIDATION, message, cause);
        this.issues = issues == null ? List.of() : List.copyOf(issues);
    }

    /** Per-field detail when the server supplied it; empty otherwise. */
    public List<Object> issues() {
        return issues;
    }
}
