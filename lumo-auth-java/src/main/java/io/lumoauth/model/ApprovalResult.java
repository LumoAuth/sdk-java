package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Optional;

/**
 * The state of a push-approval request.
 *
 * @param status  {@link #STATUS_PENDING}, {@link #STATUS_APPROVED}, {@link #STATUS_DENIED}, {@link #STATUS_EXPIRED},
 *                or {@link #STATUS_EMAIL_FALLBACK_SENT} (only from {@code create}; see {@link #emailFallbackSent()})
 * @param token   the approval token; present it as the credential for the side-effecting call the approval
 *                authorises. It is null when the status is {@link #STATUS_EMAIL_FALLBACK_SENT}.
 * @param message the server's explanation, when it sends one
 */
public record ApprovalResult(
    @JsonProperty("status") String status,
    @JsonProperty("approval_token") String token,
    @JsonProperty("task_id") String taskId,
    @JsonProperty("impact") ApprovalImpact impact,
    @JsonProperty("reason") String reason,
    @JsonProperty("expires_at") String expiresAt,
    @JsonProperty("responded_at") String respondedAt,
    @JsonProperty("approved_by") Approver approvedBy,
    @JsonProperty("message") String message
) {
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_DENIED = "denied";
    public static final String STATUS_EXPIRED = "expired";
    /**
     * The approval prompt reached no push device. LumoAuth emailed the user a notice that has no
     * approval link, and there is no approval token to poll.
     */
    public static final String STATUS_EMAIL_FALLBACK_SENT = "email_fallback_sent";

    /** The constructor without {@code message}, kept for source compatibility. */
    public ApprovalResult(String status, String token, String taskId, ApprovalImpact impact, String reason,
                          String expiresAt, String respondedAt, Approver approvedBy) {
        this(status, token, taskId, impact, reason, expiresAt, respondedAt, approvedBy, null);
    }

    /** A pending placeholder for a token, used before the first status poll. */
    public static ApprovalResult pending(String token) {
        return new ApprovalResult(STATUS_PENDING, token, null, null, null, null, null, null, null);
    }

    public boolean approved() {
        return STATUS_APPROVED.equals(status);
    }

    public boolean pending() {
        return STATUS_PENDING.equals(status);
    }

    public boolean denied() {
        return STATUS_DENIED.equals(status);
    }

    /**
     * True when the prompt reached no push device (202 {@code email_fallback_sent}). The user has no enrolled
     * device, or the user does not exist. Nobody can approve this request, so do not poll it.
     */
    public boolean emailFallbackSent() {
        return STATUS_EMAIL_FALLBACK_SENT.equals(status);
    }

    public ApprovalResult withToken(String newToken) {
        return new ApprovalResult(status, newToken, taskId, impact, reason, expiresAt, respondedAt, approvedBy, message);
    }

    public Optional<Instant> expiresAtInstant() {
        return Models.parseInstant(expiresAt);
    }
}
