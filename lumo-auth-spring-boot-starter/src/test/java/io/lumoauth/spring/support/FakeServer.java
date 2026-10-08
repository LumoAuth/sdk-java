package io.lumoauth.spring.support;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.lumoauth.internal.Json;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * A tiny in-process HTTP server for tests: canned responses per path (queued,
 * so successive calls to one path can differ), a record of every request.
 */
public final class FakeServer implements AutoCloseable {

    /** One canned response. */
    public record Reply(int status, String body, Map<String, String> headers) {
        public static Reply json(int status, Object body) {
            return new Reply(status, body instanceof String s ? s : Json.encodeToString(body), Map.of("Content-Type", "application/json"));
        }

        public static Reply json(Object body) {
            return json(200, body);
        }

        public static Reply text(int status, String body) {
            return new Reply(status, body, Map.of("Content-Type", "text/plain"));
        }

        public static Reply empty(int status) {
            return new Reply(status, "", Map.of());
        }

        public Reply header(String name, String value) {
            Map<String, String> merged = new TreeMap<>(headers);
            merged.put(name, value);
            return new Reply(status, body, merged);
        }
    }

    /** One recorded request. */
    public record Recorded(String method, String path, String query, Map<String, String> headers, String body) {
        public Map<String, Object> json() {
            return Json.toMap(Json.parse(body.getBytes(StandardCharsets.UTF_8), "request body"));
        }

        public String header(String name) {
            return headers.get(name);
        }

        public Map<String, String> form() {
            Map<String, String> out = new TreeMap<>();
            for (String pair : body.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String k = java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String v = java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                out.put(k, v);
            }
            return out;
        }
    }

    private final HttpServer server;
    private final Map<String, Deque<Reply>> replies = new ConcurrentHashMap<>();
    private final Map<String, Function<Recorded, Reply>> dynamic = new ConcurrentHashMap<>();
    private final List<Recorded> requests = new ArrayList<>();

    public FakeServer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        server.createContext("/", this::handle);
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Sets the reply for a path, replacing any earlier replies or sequence. */
    public FakeServer on(String path, Reply reply) {
        dynamic.remove(path);
        Deque<Reply> queue = new ArrayDeque<>();
        queue.add(reply);
        replies.put(path, queue);
        return this;
    }

    /** Sets a sequence of replies for a path: each request consumes one, and the last one repeats. */
    public FakeServer queue(String path, Reply... sequence) {
        dynamic.remove(path);
        Deque<Reply> queue = new ArrayDeque<>(List.of(sequence));
        replies.put(path, queue);
        return this;
    }

    /** Answers a path from a function of the request. */
    public FakeServer on(String path, Function<Recorded, Reply> fn) {
        replies.remove(path);
        dynamic.put(path, fn);
        return this;
    }

    public synchronized List<Recorded> requests() {
        return List.copyOf(requests);
    }

    public synchronized Recorded last() {
        return requests.get(requests.size() - 1);
    }

    public synchronized Recorded only() {
        if (requests.size() != 1) {
            throw new AssertionError("expected exactly one request, got " + requests.size());
        }
        return requests.get(0);
    }

    public synchronized void reset() {
        requests.clear();
    }

    private void handle(HttpExchange exchange) throws IOException {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        exchange.getRequestHeaders().forEach((k, v) -> headers.put(k, String.join(",", v)));
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String path = exchange.getRequestURI().getRawPath();
        Recorded recorded = new Recorded(exchange.getRequestMethod(), path, exchange.getRequestURI().getRawQuery(), headers, body);
        synchronized (this) {
            requests.add(recorded);
        }
        Reply reply;
        Function<Recorded, Reply> fn = dynamic.get(path);
        if (fn != null) {
            reply = fn.apply(recorded);
        } else {
            Deque<Reply> queue = replies.get(path);
            reply = queue == null || queue.isEmpty() ? Reply.json(404, Map.of("error", "not_found", "message", "no reply for " + path))
                : queue.size() > 1 ? queue.poll() : queue.peek();
        }
        reply.headers().forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
        byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0) {
            exchange.sendResponseHeaders(reply.status(), -1);
        } else {
            exchange.sendResponseHeaders(reply.status(), bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
