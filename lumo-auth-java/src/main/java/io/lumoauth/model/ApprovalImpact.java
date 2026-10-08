package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** The severity tier of an approval request; it drives the visual treatment on the approver's phone. */
public enum ApprovalImpact {
    LOW("low"),
    MEDIUM("medium"),
    HIGH("high"),
    CRITICAL("critical");

    private final String wire;

    ApprovalImpact(String wire) {
        this.wire = wire;
    }

    @JsonValue
    public String wire() {
        return wire;
    }

    /** Parses a wire value; unknown values (including null) become null rather than failing. */
    @JsonCreator
    public static ApprovalImpact fromWire(String value) {
        if (value == null) {
            return null;
        }
        for (ApprovalImpact impact : values()) {
            if (impact.wire.equalsIgnoreCase(value)) {
                return impact;
            }
        }
        return null;
    }
}
