package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Optional;

/**
 * The state of a push-approval request.
 *
 * @param status {@link #STATUS_PENDING}, {@link #STATUS_APPROVED}, {@link #STATUS_DENIED}, or {@link #STATUS_EXPIRED}
 * @param token  the approval token; present it as the credential for the side-effecting call the approval authorises
 */
public record ApprovalResult(
    @JsonProperty("status") String status,
    @JsonProperty("approval_token") String token,
    @JsonProperty("task_id") String taskId,
    @JsonProperty("impact") ApprovalImpact impact,
    @JsonProperty("reason") String reason,
    @JsonProperty("expires_at") String expiresAt,
    @JsonProperty("responded_at") String respondedAt,
    @JsonProperty("approved_by") Approver approvedBy
) {
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_DENIED = "denied";
    public static final String STATUS_EXPIRED = "expired";

    /** A pending placeholder for a token, used before the first status poll. */
    public static ApprovalResult pending(String token) {
        return new ApprovalResult(STATUS_PENDING, token, null, null, null, null, null, null);
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

    public ApprovalResult withToken(String newToken) {
        return new ApprovalResult(status, newToken, taskId, impact, reason, expiresAt, respondedAt, approvedBy);
    }

    public Optional<Instant> expiresAtInstant() {
        return Models.parseInstant(expiresAt);
    }
}
