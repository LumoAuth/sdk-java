package io.lumoauth;

import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthNetworkException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.Json;
import io.lumoauth.model.CreateTaskRequest;
import io.lumoauth.model.EvaluateTaskRequest;
import io.lumoauth.model.JitRequest;
import io.lumoauth.model.JitTask;
import io.lumoauth.model.PermissionRequest;
import io.lumoauth.model.TokenExchangeRequest;
import io.lumoauth.model.WaitOptions;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Manages one ephemeral task and the scoped permissions requested under it.
 *
 * <p>The lifecycle is: create a task, request permissions against it, exchange
 * approved requests for short-lived tokens, then complete the task, which
 * revokes every token issued under it. {@code JitContext} is
 * {@link AutoCloseable}, so try-with-resources makes that cleanup automatic:
 *
 * <pre>{@code
 * try (JitContext jit = new JitContext(agent)) {
 *     jit.createTask(CreateTaskRequest.named("Analyse Q4 report"));
 *     JitRequest result = jit.requestPermission(Map.of(
 *         "type", "file_access", "actions", List.of("read"), "identifier", "report_q4.pdf"));
 *     if (result.approved()) {
 *         String token = jit.token(result.requestId());
 *         // present the token to the resource
 *     }
 * }
 * }</pre>
 *
 * A {@code JitContext} tracks one task at a time and is not thread-safe; use
 * one per unit of work.
 */
public final class JitContext implements AutoCloseable {

    /**
     * Tunes a JIT permission request.
     *
     * @param justification   the human-readable reason shown to an approver
     * @param ttl             the requested token lifetime in seconds, capped at {@link PermissionRequest#MAX_TTL}
     * @param waitForDecision whether to poll a pending request until a human decides (default true)
     * @param polling         the polling parameters while waiting; defaults to {@link WaitOptions#JIT_DEFAULTS}
     * @param taskId          overrides the context's current task
     */
    public record RequestOptions(String justification, int ttl, boolean waitForDecision, WaitOptions polling, String taskId) {

        public static final RequestOptions DEFAULTS = new RequestOptions(null, 0, true, null, null);

        public static RequestOptions justification(String value) {
            return new RequestOptions(value, 0, true, null, null);
        }

        public RequestOptions ttl(int seconds) {
            return new RequestOptions(justification, seconds, waitForDecision, polling, taskId);
        }

        /** Return a pending request immediately instead of polling for the human decision. */
        public RequestOptions noWait() {
            return new RequestOptions(justification, ttl, false, polling, taskId);
        }

        public RequestOptions polling(WaitOptions value) {
            return new RequestOptions(justification, ttl, waitForDecision, value, taskId);
        }

        public RequestOptions taskId(String value) {
            return new RequestOptions(justification, ttl, waitForDecision, polling, value);
        }
    }

    private final TokenSource source;
    private final LumoAuth client;
    private volatile String delegatedToken;
    private volatile String taskId;
    private volatile String caepSessionId;

    /** A JIT context over an authenticated token source (normally a {@link LumoAgent}). */
    public JitContext(TokenSource source) {
        this(source, null);
    }

    /**
     * A JIT context that makes its calls under an on-behalf-of token (from
     * {@link #delegateOnBehalfOf} or a {@link DelegationChain}) instead of the source's own.
     */
    public JitContext(TokenSource source, String delegatedToken) {
        if (source == null) {
            throw new LumoAuthConfigException("a token source is required (pass a LumoAgent)");
        }
        this.source = source;
        this.delegatedToken = delegatedToken;
        this.client = LumoAuth.builder()
            .baseUrl(source.baseUrl())
            .orgId(source.orgId())
            .apiKey(null)
            .tokenProvider(this::bearer)
            .build();
    }

    /** The current task's ID, when a task is open. */
    public Optional<String> taskId() {
        return Optional.ofNullable(taskId);
    }

    /** The CAEP session ID for the current task, when the server issued one. */
    public Optional<String> caepSessionId() {
        return Optional.ofNullable(caepSessionId);
    }

    private String bearer() {
        String delegated = delegatedToken;
        if (delegated != null && !delegated.isEmpty()) {
            return delegated;
        }
        String token = source.accessToken();
        if (token == null || token.isEmpty()) {
            throw new LumoAuthConfigException("no access token available - authenticate first");
        }
        return token;
    }

    // ── Delegation ────────────────────────────────────────────────────

    /**
     * Exchanges the agent's token and a user's token for a delegated one (RFC
     * 8693) and uses it for subsequent JIT calls. The delegated token carries an
     * {@code act} claim, so the audit trail names both the user and the agent.
     */
    public void delegateOnBehalfOf(String userToken) {
        if (userToken == null || userToken.isBlank()) {
            throw new LumoAuthValidationException("a user token is required");
        }
        String agentToken = source.accessToken();
        delegatedToken = client.auth().tokenExchange(
            TokenExchangeRequest.of(userToken).actorToken(agentToken)).accessToken();
    }

    // ── Task lifecycle ────────────────────────────────────────────────

    /** Opens an ephemeral task and makes it the context's current task. */
    public JitTask createTask(CreateTaskRequest params) {
        JitTask task = client.jit().createTask(params);
        taskId = task.taskId();
        caepSessionId = task.caepSessionId();
        return task;
    }

    public JitTask createTask() {
        return createTask(CreateTaskRequest.EMPTY);
    }

    /**
     * Closes the current task and revokes its JIT tokens. A no-op when no task is
     * open; the task is cleared either way, so a failed cleanup cannot strand the
     * context on a dead task.
     */
    public void completeTask() {
        String current = taskId;
        if (current == null) {
            return;
        }
        taskId = null;
        caepSessionId = null;
        client.jit().completeTask(current);
    }

    /** {@link #completeTask} under the name try-with-resources expects. */
    @Override
    public void close() {
        completeTask();
    }

    /** Closes a task (the current one when {@code taskId} is null) with an outcome and audit notes. */
    public Map<String, Object> evaluateTask(String id, EvaluateTaskRequest params) {
        String target = id == null || id.isBlank() ? taskId : id;
        if (target == null) {
            throw new LumoAuthConfigException("no active task - call createTask first");
        }
        return client.jit().evaluateTask(target, params);
    }

    // ── Permission requests ───────────────────────────────────────────

    /**
     * Asks for a Just-in-Time permission against the current task. Low-risk
     * requests come back approved. Higher-risk ones enter human-in-the-loop
     * review; by default this polls until the request resolves or the deadline
     * passes and returns the last state seen, so a still-pending result means the
     * wait timed out, not a denial. Use {@link RequestOptions#noWait()} to poll yourself.
     */
    public JitRequest requestPermission(Map<String, Object> authorizationDetails) {
        return requestPermission(authorizationDetails, RequestOptions.DEFAULTS);
    }

    public JitRequest requestPermission(Map<String, Object> authorizationDetails, RequestOptions options) {
        RequestOptions opts = options == null ? RequestOptions.DEFAULTS : options;
        String target = opts.taskId() == null || opts.taskId().isBlank() ? taskId : opts.taskId();
        if (target == null) {
            throw new LumoAuthConfigException("no active task - call createTask first");
        }
        JitRequest result = client.jit().request(PermissionRequest.of(target, authorizationDetails)
            .justification(opts.justification())
            .ttl(opts.ttl()));
        if (result.pending() && opts.waitForDecision()) {
            return waitForApproval(result, opts.polling());
        }
        return result;
    }

    private JitRequest waitForApproval(JitRequest initial, WaitOptions options) {
        WaitOptions opts = (options == null ? WaitOptions.JIT_DEFAULTS : options).orDefaults(WaitOptions.JIT_DEFAULTS);
        Instant deadline = Instant.now().plus(opts.timeout());
        JitRequest last = initial;
        while (Instant.now().isBefore(deadline)) {
            sleep(opts.pollInterval());
            last = client.jit().status(initial.requestId());
            if (!last.pending()) {
                return last;
            }
        }
        return last; // still pending
    }

    /** The current state of a permission request. */
    public JitRequest status(String requestId) {
        return client.jit().status(requestId);
    }

    /** Exchanges an approved request for a short-lived JIT access token. */
    public String token(String requestId) {
        return client.jit().token(requestId).accessToken();
    }

    /** The requests awaiting human approval. */
    public List<JitRequest> pendingRequests() {
        return client.jit().pending();
    }

    // ── Making calls with JIT tokens ──────────────────────────────────

    /** Makes a request to any URL using a JIT token. */
    public HttpResponse<byte[]> call(String jitToken, String method, String url, Object body) {
        if (jitToken == null || jitToken.isBlank()) {
            throw new LumoAuthValidationException("a JIT token is required");
        }
        return client.transport().sendRaw(method, url, requestWith(body, jitToken));
    }

    /**
     * Makes a request and, if the server answers 403 with an
     * {@code Insufficient-Authorization-Details} header, requests exactly the
     * permission that header names, obtains a JIT token, and retries once.
     *
     * <p>This is the auto-escalation path: the resource server states what it
     * needs and the agent asks for that and nothing more. When the escalation is
     * not approved, the original 403 is returned unchanged.
     */
    public HttpResponse<byte[]> callWithEscalation(String method, String url, Object body, RequestOptions options) {
        HttpResponse<byte[]> response = client.transport().sendRaw(method, url, requestWith(body, bearer()));
        if (response.statusCode() != 403) {
            return response;
        }
        Optional<String> header = response.headers().firstValue("Insufficient-Authorization-Details");
        if (header.isEmpty()) {
            return response;
        }
        Map<String, Object> required;
        try {
            required = decodeAuthorizationDetails(header.get());
        } catch (LumoAuthValidationException e) {
            // The server's hint is unusable; hand back the original 403.
            return response;
        }
        RequestOptions opts = options == null ? RequestOptions.justification("Required for user request") : options;
        JitRequest result = requestPermission(required, opts);
        if (!result.approved()) {
            return response; // escalation refused: the original 403 stands
        }
        return call(token(result.requestId()), method, url, body);
    }

    public HttpResponse<byte[]> callWithEscalation(String method, String url, Object body) {
        return callWithEscalation(method, url, body, null);
    }

    private static ApiRequest requestWith(Object body, String bearer) {
        ApiRequest request = body == null ? ApiRequest.empty() : ApiRequest.json(body);
        return request.header("Authorization", "Bearer " + bearer);
    }

    /** Reads the base64-encoded RFC 9396 object a resource server sends in Insufficient-Authorization-Details. */
    static Map<String, Object> decodeAuthorizationDetails(String header) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(header.strip());
        } catch (IllegalArgumentException e) {
            try {
                decoded = Base64.getMimeDecoder().decode(header.strip());
            } catch (IllegalArgumentException inner) {
                throw new LumoAuthValidationException(
                    "could not base64-decode Insufficient-Authorization-Details: " + inner.getMessage(), inner);
            }
        }
        Map<String, Object> details = Json.toMap(Json.parse(decoded, "Insufficient-Authorization-Details"));
        if (details.isEmpty()) {
            throw new LumoAuthValidationException("could not decode Insufficient-Authorization-Details as a JSON object");
        }
        return details;
    }

    private static void sleep(Duration interval) {
        try {
            Thread.sleep(interval.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LumoAuthNetworkException("JIT approval polling interrupted", e);
        }
    }
}
