package io.lumoauth.errors;

/**
 * HTTP 403: the principal is authenticated but not allowed. Also raised locally
 * by capability guards such as {@code LumoAgent.requireCapability}, in which case
 * {@link #statusCode()} is 0 because no request was made.
 */
public class LumoAuthPermissionDeniedException extends LumoAuthApiException {
    public LumoAuthPermissionDeniedException(int statusCode, String code, String message, Object body) {
        super(statusCode, code, message, body);
    }

    /** A permission denial decided client-side, without a request. */
    public static LumoAuthPermissionDeniedException local(String message) {
        return new LumoAuthPermissionDeniedException(0, ErrorCodes.PERMISSION_DENIED, message, null);
    }
}
