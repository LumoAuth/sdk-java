package io.lumoauth.aauth;

import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * A framework-neutral view of a request a resource server received, for
 * proof-of-possession verification. Header names are matched case-insensitively.
 *
 * @param method  the HTTP method
 * @param uri     the request URI (the authority is read from it, or from the Host header)
 * @param headers the request headers (single values)
 * @param body    the exact body bytes received; null or empty for none
 */
public record IncomingRequest(String method, URI uri, Map<String, String> headers, byte[] body) {

    public IncomingRequest {
        TreeMap<String, String> normalised = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            normalised.putAll(headers);
        }
        headers = normalised;
    }

    public String header(String name) {
        return headers.get(name);
    }

    /** The authority the AAuth profile signs: the Host header when present, else the URI's host and port. */
    public String authority() {
        String host = header("Host");
        if (host == null || host.isBlank()) {
            host = uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
        }
        return host.toLowerCase(Locale.ROOT);
    }
}
