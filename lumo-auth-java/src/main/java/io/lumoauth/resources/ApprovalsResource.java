package io.lumoauth.resources;

import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthApiException;
import io.lumoauth.errors.LumoAuthApprovalDeniedException;
import io.lumoauth.errors.LumoAuthApprovalNotDeliveredException;
import io.lumoauth.errors.LumoAuthApprovalTimeoutException;
import io.lumoauth.errors.LumoAuthNetworkException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.model.ApprovalRequest;
import io.lumoauth.model.ApprovalResult;
import io.lumoauth.model.WaitOptions;

import java.time.Instant;
import java.util.Map;

/**
 * Push-approval-for-agent-actions.
 *
 * <p>The headline call is {@link #require}: when an agent is about to do
 * something irreversible, it asks first, a push lands on the user's phone with
 * the context, and the call returns once a human decides.
 */
public final class ApprovalsResource {

    private final HttpTransport http;

    public ApprovalsResource(HttpTransport http) {
        this.http = http;
    }

    /**
     * Opens an approval request and returns immediately with the pending approval, whose token identifies it.
     * A portal test token is refused with 403 {@code test_token_not_accepted}.
     *
     * <p>When the user has no enrolled push device, LumoAuth answers 202 {@code email_fallback_sent} and emails
     * the user a notice that has no approval link. LumoAuth gives the same answer when the user does not exist.
     * This method then returns a result whose {@link ApprovalResult#emailFallbackSent()} is true and whose token
     * is null. Nobody can approve that request, so tell the user to check their email or enrol a device.
     *
     * @throws LumoAuthApprovalNotDeliveredException with reason {@code no_enrolled_device} when LumoAuth answers
     *         428: the user has no device and the email notice could not be sent
     */
    public ApprovalResult create(ApprovalRequest params) {
        ApprovalResult result;
        try {
            result = http.call(Routes.APPROVALS_CREATE, null, ApiRequest.json(params.toBody()), ApprovalResult.class);
        } catch (LumoAuthApiException e) {
            if (e.statusCode() == 428) {
                throw new LumoAuthApprovalNotDeliveredException(
                    LumoAuthApprovalNotDeliveredException.REASON_NO_ENROLLED_DEVICE,
                    e.bodyField("task_id").orElse(null),
                    e.bodyField("message").orElse(e.getMessage()),
                    e);
            }
            throw e;
        }
        if (result != null && result.emailFallbackSent()) {
            return result;
        }
        if (result == null || result.token() == null || result.token().isEmpty()) {
            throw new LumoAuthValidationException("the server did not return an approval_token");
        }
        return result;
    }

    /** The current state of an approval. Read-only, so safe to expose to a polling frontend. */
    public ApprovalResult status(String approvalToken) {
        if (approvalToken == null || approvalToken.isBlank()) {
            throw new LumoAuthValidationException("an approval token is required");
        }
        ApprovalResult result = http.call(Routes.APPROVALS_STATUS, Map.of("token", approvalToken), null, ApprovalResult.class);
        if (result == null) {
            throw new LumoAuthValidationException("the approval status endpoint returned no body");
        }
        return result.token() == null || result.token().isEmpty() ? result.withToken(approvalToken) : result;
    }

    /**
     * Polls an approval until it leaves pending or the deadline passes, returning
     * the last observed state. A still-pending result means the wait timed out,
     * not that the request was denied.
     */
    public ApprovalResult waitFor(String approvalToken, WaitOptions options) {
        WaitOptions opts = (options == null ? WaitOptions.APPROVAL_DEFAULTS : options).orDefaults(WaitOptions.APPROVAL_DEFAULTS);
        Instant deadline = Instant.now().plus(opts.timeout());
        ApprovalResult last = ApprovalResult.pending(approvalToken);
        while (Instant.now().isBefore(deadline)) {
            sleep(opts.pollInterval().toMillis(), "approval polling");
            last = status(approvalToken);
            if (!last.pending()) {
                return last;
            }
        }
        return last;
    }

    /** {@link #waitFor} with the default polling parameters. */
    public ApprovalResult waitFor(String approvalToken) {
        return waitFor(approvalToken, null);
    }

    /**
     * Opens an approval request and blocks until a human decides. Anything other
     * than approval is an exception, so the happy path reads as a guard:
     *
     * <pre>{@code
     * ApprovalResult approval = lumo.approvals().require(
     *     ApprovalRequest.builder("wire-001", "Wire $4,500 to vendor INV-7741", "ada@acme.com")
     *         .impact(ApprovalImpact.HIGH).build());
     * // approval.token() authorises the side-effecting call.
     * }</pre>
     *
     * Catch {@link LumoAuthApprovalDeniedException} and {@link LumoAuthApprovalTimeoutException}
     * to tell the outcomes apart; both carry the final payload for audit. To handle a
     * denial without an exception, call {@link #create} and {@link #waitFor} yourself.
     *
     * <p>When the prompt reaches no push device, this method throws
     * {@link LumoAuthApprovalNotDeliveredException} and does not poll. Its reason is
     * {@code email_fallback_sent} (202) or {@code no_enrolled_device} (428).
     */
    public ApprovalResult require(ApprovalRequest params) {
        return require(params, null);
    }

    public ApprovalResult require(ApprovalRequest params, WaitOptions options) {
        ApprovalResult created = create(params);
        if (created.emailFallbackSent()) {
            throw new LumoAuthApprovalNotDeliveredException(
                LumoAuthApprovalNotDeliveredException.REASON_EMAIL_FALLBACK_SENT, created.taskId(), created.message());
        }
        ApprovalResult result = waitFor(created.token(), options);
        if (result.approved()) {
            return result;
        }
        if (result.denied()) {
            throw new LumoAuthApprovalDeniedException(result);
        }
        // Pending at the deadline, or expired server-side.
        throw new LumoAuthApprovalTimeoutException(result);
    }

    static void sleep(long millis, String what) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LumoAuthNetworkException(what + " interrupted", e);
        }
    }
}
