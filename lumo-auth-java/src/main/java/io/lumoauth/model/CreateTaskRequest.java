package io.lumoauth.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An ephemeral task.
 *
 * @param name       a human-readable label ("Analyse Q4 report").
 * @param type       a category ("research", "analysis").
 * @param onBehalfOf the user's email when the agent acts for someone.
 */
public record CreateTaskRequest(String name, String type, String onBehalfOf) {

    public static final CreateTaskRequest EMPTY = new CreateTaskRequest(null, null, null);

    public static CreateTaskRequest named(String name) {
        return new CreateTaskRequest(name, null, null);
    }

    public CreateTaskRequest type(String newType) {
        return new CreateTaskRequest(name, newType, onBehalfOf);
    }

    public CreateTaskRequest onBehalfOf(String user) {
        return new CreateTaskRequest(name, type, user);
    }

    public Map<String, Object> toBody() {
        Map<String, Object> body = new LinkedHashMap<>();
        if (name != null && !name.isBlank()) {
            body.put("name", name);
        }
        if (type != null && !type.isBlank()) {
            body.put("type", type);
        }
        if (onBehalfOf != null && !onBehalfOf.isBlank()) {
            body.put("on_behalf_of", onBehalfOf);
        }
        return body;
    }
}
