package io.lumoauth.model;

import java.util.Map;

/**
 * A response type that keeps the complete decoded object alongside its typed
 * fields. The LumoAuth API is still growing response fields, so a field this
 * SDK does not model yet is still reachable through {@link #raw()} without
 * dropping to the escape hatch.
 */
public interface RawPayload<T extends RawPayload<T>> {

    /** The complete decoded response object (never null; empty when unknown). */
    Map<String, Object> raw();

    /** A copy carrying the given raw object. Called by the SDK after decoding. */
    T withRaw(Map<String, Object> raw);
}
