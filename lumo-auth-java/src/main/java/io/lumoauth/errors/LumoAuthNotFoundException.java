package io.lumoauth.errors;

/** HTTP 404. */
public class LumoAuthNotFoundException extends LumoAuthApiException {
    public LumoAuthNotFoundException(int statusCode, String code, String message, Object body) {
        super(statusCode, code, message, body);
    }
}
