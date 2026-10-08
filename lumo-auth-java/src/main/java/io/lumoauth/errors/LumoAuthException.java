package io.lumoauth.errors;

/**
 * Base class of every exception this SDK throws. All are unchecked, so the
 * happy path stays uncluttered and callers catch the subclass they care about:
 *
 * <pre>{@code
 * LumoAuthException                      every SDK error
 * ├── LumoAuthApiException               any non-2xx HTTP response
 * │   ├── LumoAuthAuthenticationException    401
 * │   ├── LumoAuthPermissionDeniedException  403
 * │   ├── LumoAuthNotFoundException          404
 * │   └── LumoAuthRateLimitException         429 (carries Retry-After)
 * ├── LumoAuthValidationException        bad input, or a response shape the SDK cannot use
 * ├── LumoAuthConfigException            missing or invalid configuration
 * ├── LumoAuthNetworkException           transport failure (DNS, TLS, timeout, interrupt)
 * ├── LumoAuthApprovalDeniedException    a human declined the action
 * ├── LumoAuthApprovalTimeoutException   nobody responded in time
 * └── LumoAuthBudgetExceededException    the agent's budget is spent
 * }</pre>
 *
 * {@link #code()} is the stable code shared with the other SDKs ({@link ErrorCodes}).
 */
public class LumoAuthException extends RuntimeException {

    private final String code;

    public LumoAuthException(String message) {
        this(ErrorCodes.ERROR, message, null);
    }

    public LumoAuthException(String message, Throwable cause) {
        this(ErrorCodes.ERROR, message, cause);
    }

    protected LumoAuthException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code == null || code.isEmpty() ? ErrorCodes.ERROR : code;
    }

    /** The machine-readable error code (one of {@link ErrorCodes}, or a server-supplied code). */
    public String code() {
        return code;
    }
}
