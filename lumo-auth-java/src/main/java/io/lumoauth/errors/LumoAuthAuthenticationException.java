package io.lumoauth.errors;

/** HTTP 401: the credential is missing, invalid, or expired. */
public class LumoAuthAuthenticationException extends LumoAuthApiException {
    public LumoAuthAuthenticationException(int statusCode, String code, String message, Object body) {
        super(statusCode, code, message, body);
    }
}
