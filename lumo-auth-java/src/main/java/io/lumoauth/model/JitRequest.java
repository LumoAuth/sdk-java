package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * The state of a Just-in-Time permission request.
 *
 * @param status {@link #STATUS_APPROVED}, {@link #STATUS_PENDING}, {@link #STATUS_DENIED}, or a newer server value
 */
public record JitRequest(
    @JsonProperty("request_id") String requestId,
    @JsonProperty("status") String status,
    @JsonProperty("risk_level") String riskLevel,
    @JsonProperty("task_id") String taskId,
    @JsonProperty("token_url") String tokenUrl,
    @JsonProperty("status_url") String statusUrl,
    @JsonProperty("expires_at") String expiresAt,
    @JsonProperty("granted_ttl") int grantedTtl,
    @JsonProperty("authorization_details") Map<String, Object> authorizationDetails,
    Map<String, Object> raw
) implements RawPayload<JitRequest> {

    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_DENIED = "denied";

    public JitRequest {
        authorizationDetails = Models.map(authorizationDetails);
        raw = Models.map(raw);
    }

    @Override
    public JitRequest withRaw(Map<String, Object> newRaw) {
        return new JitRequest(requestId, status, riskLevel, taskId, tokenUrl, statusUrl, expiresAt,
            grantedTtl, authorizationDetails, newRaw);
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

    public Optional<Instant> expiresAtInstant() {
        return Models.parseInstant(expiresAt);
    }
}
