package io.lumoauth.model;

import java.time.Duration;

/**
 * Polling parameters for blocking waits (approvals and JIT requests).
 *
 * @param pollInterval the delay between status polls
 * @param timeout      the longest total wait
 */
public record WaitOptions(Duration pollInterval, Duration timeout) {

    /** Approval defaults: 1.5s polls, 90s deadline (the server's push request TTL is 120s). */
    public static final WaitOptions APPROVAL_DEFAULTS = new WaitOptions(Duration.ofMillis(1500), Duration.ofSeconds(90));
    /** JIT defaults: 5s polls, 5 minute deadline. */
    public static final WaitOptions JIT_DEFAULTS = new WaitOptions(Duration.ofSeconds(5), Duration.ofMinutes(5));

    public static WaitOptions of(Duration pollInterval, Duration timeout) {
        return new WaitOptions(pollInterval, timeout);
    }

    /** This instance with any missing or non-positive value replaced by the given defaults. */
    public WaitOptions orDefaults(WaitOptions defaults) {
        Duration interval = pollInterval == null || pollInterval.isZero() || pollInterval.isNegative()
            ? defaults.pollInterval() : pollInterval;
        Duration limit = timeout == null || timeout.isZero() || timeout.isNegative() ? defaults.timeout() : timeout;
        return new WaitOptions(interval, limit);
    }
}
