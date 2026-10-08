package io.lumoauth.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * How a task ended, for the audit record.
 *
 * @param result defaults to {@link TaskResult#COMPLETED}
 * @param notes  attached to the audit record
 */
public record EvaluateTaskRequest(TaskResult result, String notes) {

    public static EvaluateTaskRequest completed() {
        return new EvaluateTaskRequest(TaskResult.COMPLETED, null);
    }

    public static EvaluateTaskRequest of(TaskResult result, String notes) {
        return new EvaluateTaskRequest(result, notes);
    }

    public Map<String, Object> toBody() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("result", (result == null ? TaskResult.COMPLETED : result).wire());
        if (notes != null && !notes.isBlank()) {
            body.put("notes", notes);
        }
        return body;
    }
}
