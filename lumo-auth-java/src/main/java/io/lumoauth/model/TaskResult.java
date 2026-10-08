package io.lumoauth.model;

/** How a JIT task ended. */
public enum TaskResult {
    COMPLETED("completed"),
    FAILED("failed"),
    CANCELLED("cancelled");

    private final String wire;

    TaskResult(String wire) {
        this.wire = wire;
    }

    public String wire() {
        return wire;
    }
}
