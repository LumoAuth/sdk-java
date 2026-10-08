package io.lumoauth.model;

/** ABAC attribute kinds accepted when listing definitions. */
public enum AttributeType {
    USER("user"),
    RESOURCE("resource"),
    ENVIRONMENT("environment");

    private final String wire;

    AttributeType(String wire) {
        this.wire = wire;
    }

    /** The value on the wire. */
    public String wire() {
        return wire;
    }
}
