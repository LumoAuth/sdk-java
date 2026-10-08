package io.lumoauth.internal;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One outbound call. Internal; resources build these.
 *
 * <p>Exactly one body kind applies: {@link #withJson(Object)} is encoded with
 * {@code Content-Type: application/json}, {@link #withRaw(byte[])} is sent verbatim
 * (AAuth signs exact bytes), {@link #withForm(Map)} is sent URL-encoded (OAuth
 * endpoints).
 */
public final class ApiRequest {

    private Object json;
    private byte[] raw;
    private Map<String, String> form;
    private final Map<String, String> query = new LinkedHashMap<>();
    private final Map<String, String> headers = new LinkedHashMap<>();
    private boolean noAuth;
    private Duration timeout;

    public static ApiRequest empty() {
        return new ApiRequest();
    }

    public static ApiRequest json(Object body) {
        return new ApiRequest().withJson(body);
    }

    public ApiRequest withJson(Object body) {
        this.json = body;
        return this;
    }

    public ApiRequest withRaw(byte[] body) {
        this.raw = body;
        return this;
    }

    public ApiRequest withForm(Map<String, String> form) {
        this.form = form;
        return this;
    }

    public ApiRequest query(String name, String value) {
        if (value != null) {
            query.put(name, value);
        }
        return this;
    }

    public ApiRequest header(String name, String value) {
        if (value != null) {
            headers.put(name, value);
        }
        return this;
    }

    public ApiRequest headers(Map<String, String> values) {
        if (values != null) {
            headers.putAll(values);
        }
        return this;
    }

    /** Suppresses credential injection (OAuth token endpoints authenticate through the form body). */
    public ApiRequest noAuth() {
        this.noAuth = true;
        return this;
    }

    public ApiRequest timeout(Duration timeout) {
        this.timeout = timeout;
        return this;
    }

    Object jsonBody() {
        return json;
    }

    byte[] rawBody() {
        return raw;
    }

    Map<String, String> formBody() {
        return form;
    }

    Map<String, String> queryParams() {
        return query;
    }

    Map<String, String> headerValues() {
        return headers;
    }

    boolean isNoAuth() {
        return noAuth;
    }

    Duration timeoutOverride() {
        return timeout;
    }
}
