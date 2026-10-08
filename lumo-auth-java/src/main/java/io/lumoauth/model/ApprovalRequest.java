package io.lumoauth.model;

import io.lumoauth.errors.LumoAuthValidationException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A push-approval request.
 *
 * <pre>{@code
 * ApprovalRequest.builder("wire-001", "Wire $4,500 to vendor INV-7741", "ada@acme.com")
 *     .impact(ApprovalImpact.HIGH)
 *     .meta(Map.of("amount", 4500, "vendor", "INV-7741"))
 *     .build();
 * }</pre>
 *
 * @param taskId     the task the agent is operating against. Required.
 * @param reason     the description shown on the approver's phone. Required.
 * @param onBehalfOf the user the agent is acting for (email or user ID). Required.
 * @param impact     the severity tier; defaults to {@link ApprovalImpact#MEDIUM}.
 * @param meta       structured fields (vendor, amount, ...) shown to the user.
 */
public record ApprovalRequest(String taskId, String reason, String onBehalfOf, ApprovalImpact impact, Map<String, Object> meta) {

    public ApprovalRequest {
        impact = impact == null ? ApprovalImpact.MEDIUM : impact;
        meta = Models.map(meta);
    }

    public static Builder builder(String taskId, String reason, String onBehalfOf) {
        return new Builder(taskId, reason, onBehalfOf);
    }

    public Map<String, Object> toBody() {
        if (taskId == null || taskId.isBlank()) {
            throw new LumoAuthValidationException("taskId is required");
        }
        if (reason == null || reason.isBlank()) {
            throw new LumoAuthValidationException("reason is required");
        }
        if (onBehalfOf == null || onBehalfOf.isBlank()) {
            throw new LumoAuthValidationException("onBehalfOf is required");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("task_id", taskId);
        body.put("reason", reason);
        body.put("impact", impact.wire());
        body.put("on_behalf_of", onBehalfOf);
        if (!meta.isEmpty()) {
            body.put("meta", meta);
        }
        return body;
    }

    public static final class Builder {
        private final String taskId;
        private final String reason;
        private final String onBehalfOf;
        private ApprovalImpact impact;
        private Map<String, Object> meta;

        private Builder(String taskId, String reason, String onBehalfOf) {
            this.taskId = taskId;
            this.reason = reason;
            this.onBehalfOf = onBehalfOf;
        }

        public Builder impact(ApprovalImpact value) {
            this.impact = value;
            return this;
        }

        public Builder meta(Map<String, Object> value) {
            this.meta = value;
            return this;
        }

        public ApprovalRequest build() {
            return new ApprovalRequest(taskId, reason, onBehalfOf, impact, meta);
        }
    }
}
