package io.lumoauth.errors;

/**
 * The stable, machine-readable error codes shared by every LumoAuth SDK
 * (see {@code sdk-contract/errors.json}). Each exception class carries exactly
 * one of these unless the server supplied a more specific code.
 */
public final class ErrorCodes {
    public static final String ERROR = "LUMOAUTH_ERROR";
    public static final String API = "API_ERROR";
    public static final String AUTHENTICATION = "AUTHENTICATION_ERROR";
    public static final String PERMISSION_DENIED = "PERMISSION_DENIED";
    public static final String NOT_FOUND = "NOT_FOUND";
    public static final String RATE_LIMITED = "RATE_LIMITED";
    public static final String VALIDATION = "VALIDATION_ERROR";
    public static final String CONFIG = "CONFIG_ERROR";
    public static final String NETWORK = "NETWORK_ERROR";
    public static final String APPROVAL_DENIED = "APPROVAL_DENIED";
    public static final String APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT";
    public static final String BUDGET_EXCEEDED = "BUDGET_EXCEEDED";
    public static final String APPROVAL_NOT_DELIVERED = "APPROVAL_NOT_DELIVERED";

    private ErrorCodes() {
    }

    /** The default code for an HTTP status, used when the response body names none. */
    public static String forStatus(int status) {
        return switch (status) {
            case 401 -> AUTHENTICATION;
            case 403 -> PERMISSION_DENIED;
            case 404 -> NOT_FOUND;
            case 429 -> RATE_LIMITED;
            default -> API;
        };
    }
}
