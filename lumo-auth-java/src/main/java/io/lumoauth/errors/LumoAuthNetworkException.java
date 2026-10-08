package io.lumoauth.errors;

/**
 * The request failed before an HTTP response was received: DNS, connection,
 * TLS, timeout, or the calling thread was interrupted while waiting.
 */
public class LumoAuthNetworkException extends LumoAuthException {
    public LumoAuthNetworkException(String message, Throwable cause) {
        super(ErrorCodes.NETWORK, message, cause);
    }
}
