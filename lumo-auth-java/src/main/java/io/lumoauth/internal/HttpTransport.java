package io.lumoauth.internal;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.Routes;
import io.lumoauth.TokenProvider;
import io.lumoauth.Version;
import io.lumoauth.errors.LumoAuthApiException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthNetworkException;
import io.lumoauth.errors.LumoAuthValidationException;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * The transport shared by every resource namespace. It
 * <ul>
 *   <li>injects credentials: a {@link TokenProvider} yields a bearer token
 *       ({@code Authorization: Bearer ...}), an API key is sent as {@code X-API-Key}.
 *       The two are never sent together, since the server rejects ambiguous credentials;</li>
 *   <li>maps error statuses onto the exception taxonomy, reading
 *       {@code error / code / error_description / message} out of JSON bodies;</li>
 *   <li>wraps transport failures in {@link LumoAuthNetworkException};</li>
 *   <li>decodes successful JSON responses.</li>
 * </ul>
 * Internal: obtain one through {@code LumoAuth.transport()}.
 */
public final class HttpTransport {

    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /** Everything a transport needs; {@code null} fields take their defaults. */
    public record Config(
        String baseUrl,
        String orgId,
        String apiKey,
        TokenProvider tokenProvider,
        Duration timeout,
        HttpClient httpClient,
        boolean skipCertValidation,
        Map<String, String> headers,
        String userAgent
    ) {
    }

    private final String baseUrl;
    private final String orgId;
    private final String apiKey;
    private final TokenProvider tokenProvider;
    private final Duration timeout;
    private final HttpClient httpClient;
    private final Map<String, String> headers;
    private final String userAgent;

    public HttpTransport(Config cfg) {
        if (cfg.baseUrl() == null || cfg.baseUrl().isBlank()) {
            throw new LumoAuthConfigException("a base URL is required");
        }
        this.baseUrl = stripTrailingSlash(cfg.baseUrl());
        this.orgId = emptyToNull(cfg.orgId());
        this.apiKey = emptyToNull(cfg.apiKey());
        this.tokenProvider = cfg.tokenProvider();
        this.timeout = cfg.timeout() == null || cfg.timeout().isZero() || cfg.timeout().isNegative()
            ? DEFAULT_TIMEOUT : cfg.timeout();
        this.headers = cfg.headers() == null ? Map.of() : Map.copyOf(cfg.headers());
        this.userAgent = cfg.userAgent() == null || cfg.userAgent().isBlank() ? Version.userAgent() : cfg.userAgent();
        this.httpClient = cfg.httpClient() != null ? cfg.httpClient() : buildClient(this.timeout, cfg.skipCertValidation());
    }

    private static HttpClient buildClient(Duration timeout, boolean skipCertValidation) {
        HttpClient.Builder builder = HttpClient.newBuilder()
            .connectTimeout(timeout)
            .followRedirects(HttpClient.Redirect.NEVER);
        if (skipCertValidation) {
            // Local development only. java.net.http has no per-client hostname
            // verification switch, so the system property is set as well.
            System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
            builder.sslContext(trustAllContext());
        }
        return builder.build();
    }

    private static SSLContext trustAllContext() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, null);
            return context;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new LumoAuthConfigException("could not build an insecure TLS context: " + e.getMessage());
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────

    public String baseUrl() {
        return baseUrl;
    }

    public Optional<String> orgId() {
        return Optional.ofNullable(orgId);
    }

    public Optional<String> apiKey() {
        return Optional.ofNullable(apiKey);
    }

    public HttpClient httpClient() {
        return httpClient;
    }

    public Duration timeout() {
        return timeout;
    }

    /** The current bearer token from the provider, or empty when there is none. */
    public Optional<String> bearerToken() {
        if (tokenProvider == null) {
            return Optional.empty();
        }
        String token = tokenProvider.token();
        return token == null || token.isEmpty() ? Optional.empty() : Optional.of(token);
    }

    // ── Route resolution ──────────────────────────────────────────────

    /** Resolves a route name plus params to a concrete method and path, filling {orgId} from the client. */
    public Routes.Route resolve(String routeName, Map<String, String> params) {
        Routes.Route route = Routes.get(routeName);
        Map<String, String> filled = new LinkedHashMap<>();
        if (params != null) {
            filled.putAll(params);
        }
        if (route.path().contains("{orgId}") && isBlank(filled.get("orgId"))) {
            if (orgId == null) {
                throw new LumoAuthConfigException(
                    "org ID is required for \"" + routeName + "\" - pass orgId to the builder or set LUMOAUTH_ORG_ID");
            }
            filled.put("orgId", orgId);
        }
        return new Routes.Route(route.method(), Routes.buildPath(route.path(), filled));
    }

    /** Prefixes a path with the org-scoped API base. */
    public String orgPath(String path) {
        if (orgId == null) {
            throw new LumoAuthConfigException(
                "org ID is required for this call - pass orgId to the builder or set LUMOAUTH_ORG_ID");
        }
        return Routes.buildPath(Routes.ORG_SCOPED_PREFIX, Map.of("orgId", orgId)) + path;
    }

    // ── Calls ─────────────────────────────────────────────────────────

    /** Invokes a registry route and decodes the response into {@code type} (null for no body). */
    public <T> T call(String routeName, Map<String, String> params, ApiRequest request, Class<T> type) {
        Routes.Route route = resolve(routeName, params);
        return send(route.method(), route.path(), request, type);
    }

    /** Invokes a registry route and returns the decoded JSON tree (null for an empty body). */
    public JsonNode callNode(String routeName, Map<String, String> params, ApiRequest request) {
        Routes.Route route = resolve(routeName, params);
        return sendNode(route.method(), route.path(), request);
    }

    /** Sends to a path (joined to the base URL) or an absolute URL and decodes the response. */
    public <T> T send(String method, String pathOrUrl, ApiRequest request, Class<T> type) {
        JsonNode node = sendNode(method, pathOrUrl, request);
        if (type == null || node == null) {
            return null;
        }
        return Json.convert(node, type, pathOrUrl);
    }

    /** Sends and returns the decoded JSON tree, mapping non-2xx statuses to exceptions. */
    public JsonNode sendNode(String method, String pathOrUrl, ApiRequest request) {
        HttpResponse<byte[]> response = sendRaw(method, pathOrUrl, request);
        byte[] body = response.body();
        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            throw errorFromResponse(response);
        }
        if (status == 204 || body == null || isBlank(body)) {
            return null;
        }
        return Json.parse(body, pathOrUrl);
    }

    /**
     * Performs the request and returns the response untouched: transport failures
     * are wrapped, HTTP statuses are not interpreted.
     */
    public HttpResponse<byte[]> sendRaw(String method, String pathOrUrl, ApiRequest request) {
        ApiRequest req = request == null ? ApiRequest.empty() : request;
        String target = pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
            ? pathOrUrl : baseUrl + pathOrUrl;
        if (!req.queryParams().isEmpty()) {
            target += (target.contains("?") ? "&" : "?") + formEncode(req.queryParams());
        }

        HttpRequest.BodyPublisher publisher = HttpRequest.BodyPublishers.noBody();
        String contentType = null;
        if (req.formBody() != null) {
            publisher = HttpRequest.BodyPublishers.ofString(formEncode(req.formBody()), StandardCharsets.UTF_8);
            contentType = "application/x-www-form-urlencoded";
        } else if (req.rawBody() != null) {
            publisher = HttpRequest.BodyPublishers.ofByteArray(req.rawBody());
            contentType = "application/json";
        } else if (req.jsonBody() != null) {
            publisher = HttpRequest.BodyPublishers.ofByteArray(Json.encode(req.jsonBody()));
            contentType = "application/json";
        }

        HttpRequest.Builder builder;
        try {
            builder = HttpRequest.newBuilder(URI.create(target));
        } catch (IllegalArgumentException e) {
            throw new LumoAuthValidationException("could not build the request for " + target + ": " + e.getMessage(), e);
        }
        builder.method(method.toUpperCase(Locale.ROOT), publisher)
            .timeout(req.timeoutOverride() != null ? req.timeoutOverride() : timeout)
            .header("Accept", "application/json")
            .header("User-Agent", userAgent);
        if (contentType != null) {
            builder.header("Content-Type", contentType);
        }
        Map<String, String> merged = new LinkedHashMap<>(headers);
        merged.putAll(req.headerValues());
        final boolean hasBodyType = contentType != null;
        merged.forEach((k, v) -> {
            if (!hasBodyType || !"Content-Type".equalsIgnoreCase(k)) {
                builder.setHeader(k, v);
            }
        });
        injectCredentials(builder, merged, req);

        try {
            return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new LumoAuthNetworkException("request to " + target + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LumoAuthNetworkException("request to " + target + " was interrupted", e);
        }
    }

    /** Adds exactly one credential header, unless the caller supplied one or asked for none. */
    private void injectCredentials(HttpRequest.Builder builder, Map<String, String> present, ApiRequest req) {
        if (req.isNoAuth()) {
            return;
        }
        for (String name : present.keySet()) {
            if (name.equalsIgnoreCase("Authorization") || name.equalsIgnoreCase("X-API-Key")) {
                return;
            }
        }
        Optional<String> bearer = bearerToken();
        if (bearer.isPresent()) {
            builder.setHeader("Authorization", "Bearer " + bearer.get());
            return;
        }
        if (apiKey != null) {
            // API keys travel in X-API-Key, leaving Authorization free for
            // bearer tokens. Sending both is a server-side error.
            builder.setHeader("X-API-Key", apiKey);
        }
    }

    // ── Error mapping ─────────────────────────────────────────────────

    /** Builds the typed exception for a non-2xx response. */
    public static LumoAuthApiException errorFromResponse(HttpResponse<byte[]> response) {
        int status = response.statusCode();
        Object parsed = parseBody(response.body());
        String message = "HTTP " + status + " " + reasonPhrase(status);
        String code = null;
        if (parsed instanceof Map<?, ?> map) {
            for (String key : List.of("error_description", "message", "detail", "error")) {
                if (map.get(key) instanceof String s && !s.isEmpty()) {
                    message = s;
                    break;
                }
            }
            for (String key : List.of("code", "error")) {
                if (map.get(key) instanceof String s && !s.isEmpty()) {
                    code = s;
                    break;
                }
            }
        } else if (parsed instanceof String s && !s.isBlank()) {
            String trimmed = s.strip();
            if (trimmed.length() > 500) {
                trimmed = trimmed.substring(0, 500);
            }
            message = "HTTP " + status + " - " + trimmed;
        }
        Duration retryAfter = status == 429
            ? parseRetryAfter(response.headers().firstValue("Retry-After").orElse(null)) : null;
        return LumoAuthApiException.of(status, code, message, parsed, retryAfter);
    }

    /** Decodes a body: a map for JSON objects, a list for arrays, the string otherwise, null when empty. */
    static Object parseBody(byte[] body) {
        if (body == null || isBlank(body)) {
            return null;
        }
        // Try JSON regardless of Content-Type; some endpoints omit it.
        JsonNode node = Json.tryParse(body);
        if (node != null && !node.isMissingNode()) {
            if (node.isObject()) {
                return Collections.unmodifiableMap(Json.toMap(node));
            }
            if (node.isArray() || node.isValueNode()) {
                Object value = Json.toValue(node);
                if (value != null) {
                    return value;
                }
            }
        }
        return new String(body, StandardCharsets.UTF_8);
    }

    /** Test hook for {@link #parseRetryAfter}. */
    public static Duration parseRetryAfterForTest(String value) {
        return parseRetryAfter(value);
    }

    /** Reads Retry-After as delay-seconds or an HTTP date. */
    static Duration parseRetryAfter(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.strip();
        try {
            double seconds = Double.parseDouble(trimmed);
            return seconds < 0 ? null : Duration.ofMillis((long) (seconds * 1000));
        } catch (NumberFormatException ignored) {
            // fall through to the date form
        }
        try {
            ZonedDateTime when = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME);
            Duration delay = Duration.between(ZonedDateTime.now(when.getZone()), when);
            return delay.isNegative() ? null : delay;
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    static String reasonPhrase(int status) {
        return switch (status) {
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 409 -> "Conflict";
            case 410 -> "Gone";
            case 422 -> "Unprocessable Entity";
            case 429 -> "Too Many Requests";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            case 504 -> "Gateway Timeout";
            default -> "";
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────

    public static String formEncode(Map<String, String> values) {
        return values.entrySet().stream()
            .filter(e -> e.getValue() != null)
            .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
    }

    static String stripTrailingSlash(String url) {
        String out = url.strip();
        while (out.endsWith("/")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }

    static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    static boolean isBlank(byte[] body) {
        for (byte b : body) {
            if (b != ' ' && b != '\n' && b != '\r' && b != '\t') {
                return false;
            }
        }
        return true;
    }
}
