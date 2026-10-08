package io.lumoauth.spring;

import io.lumoauth.aauth.IncomingRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.net.URI;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Adapts a servlet request for AAuth proof-of-possession verification:
 *
 * <pre>{@code
 * AAuthClaims claims = AAuthVerifier.verifyAuthToken(bearer, verifyOptions);
 * claims.verifyProofOfPossession(ServletRequests.toIncomingRequest(request, body));
 * }</pre>
 *
 * The body must be the exact bytes received (read it once, e.g. through a
 * {@code ContentCachingRequestWrapper}), since Content-Digest is computed over them.
 */
public final class ServletRequests {

    private ServletRequests() {
    }

    public static IncomingRequest toIncomingRequest(HttpServletRequest request, byte[] body) {
        Map<String, String> headers = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            headers.put(name, request.getHeader(name));
        }
        StringBuilder url = new StringBuilder(request.getRequestURL());
        if (request.getQueryString() != null && !request.getQueryString().isEmpty()) {
            url.append('?').append(request.getQueryString());
        }
        return new IncomingRequest(request.getMethod(), URI.create(url.toString()), headers, body);
    }
}
