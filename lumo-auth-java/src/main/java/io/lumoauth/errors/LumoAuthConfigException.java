package io.lumoauth.errors;

/** A required option is missing or invalid (no credential, no org ID, unknown route, ...). */
public class LumoAuthConfigException extends LumoAuthException {
    public LumoAuthConfigException(String message) {
        super(ErrorCodes.CONFIG, message, null);
    }
}
