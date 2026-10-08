package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/** An ephemeral JIT task: an isolated agent sub-identity that permissions attach to. */
public record JitTask(
    @JsonProperty("task_id") String taskId,
    @JsonProperty("caep_session_id") String caepSessionId,
    @JsonProperty("expires_at") String expiresAt,
    Map<String, Object> raw
) implements RawPayload<JitTask> {

    public JitTask {
        raw = Models.map(raw);
    }

    @Override
    public JitTask withRaw(Map<String, Object> newRaw) {
        return new JitTask(taskId, caepSessionId, expiresAt, newRaw);
    }

    public Optional<Instant> expiresAtInstant() {
        return Models.parseInstant(expiresAt);
    }
}
