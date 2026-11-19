package io.lumoauth;

import java.util.Collection;

/**
 * Agent capability matching, exactly as the LumoAuth server does it.
 *
 * <p>A capability is one of the agent's OAuth scope values, in the form
 * {@code <resource>:<action>} ({@code invoices:read}, {@code web:search}).
 * LumoAuth refuses the dot form ({@code invoices.read}) when a capability is
 * registered or a scope is requested for its API. The server compares
 * capabilities in one canonical form with two wildcards, so comparing
 * capability strings with {@code equals} gets both wrong: a dotted permission
 * slug such as {@code invoices.read} compares equal to {@code invoices:read},
 * and {@code invoices:*} covers {@code invoices:read}.
 *
 * <ul>
 *   <li><b>Canonical form</b> (used only to compare). Trimmed, ASCII letters
 *       lower-cased, {@code .} turned into {@code :}, runs of {@code :}
 *       collapsed, {@code :} trimmed from both ends. A {@code -} is part of a
 *       name ({@code pull-requests:comment}), not a separator.</li>
 *   <li><b>Wildcards.</b> {@code *} covers every action. A name that ends in
 *       {@code :*} covers every action under that prefix, at any depth, but not
 *       the prefix itself: {@code invoices:*} covers {@code invoices:read},
 *       never {@code invoices}. A {@code *} anywhere else is an ordinary
 *       character.</li>
 * </ul>
 *
 * <p>The cases in {@code sdk-contract/vectors/agent-capabilities.json} are
 * checked against the server's own matcher, and {@code CapabilitiesTest}
 * checks this class against the same cases.
 */
public final class Capabilities {

    /** The bare wildcard that covers every action. */
    public static final String WILDCARD = "*";

    /** Separates the resource from the action, and further parts. */
    private static final char SEPARATOR = ':';

    private Capabilities() {
    }

    /**
     * Returns a capability in the canonical form that the server compares:
     * {@code "Invoices.Read"} and {@code "invoices::read"} both become
     * {@code "invoices:read"}, while {@code "invoices-read"} stays as it is.
     * Only ASCII letters are lower-cased, as on the server.
     */
    public static String normalize(String capability) {
        if (capability == null) {
            return "";
        }
        int start = 0;
        int end = capability.length();
        while (start < end && isTrimmed(capability.charAt(start))) {
            start++;
        }
        while (end > start && isTrimmed(capability.charAt(end - 1))) {
            end--;
        }
        StringBuilder out = new StringBuilder(end - start);
        boolean lastSeparator = false;
        for (int i = start; i < end; i++) {
            char c = capability.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + ('a' - 'A'));
            } else if (c == '.') {
                c = SEPARATOR;
            }
            if (c == SEPARATOR) {
                if (lastSeparator) {
                    continue;
                }
                lastSeparator = true;
            } else {
                lastSeparator = false;
            }
            out.append(c);
        }
        int from = 0;
        int to = out.length();
        while (from < to && out.charAt(from) == SEPARATOR) {
            from++;
        }
        while (to > from && out.charAt(to - 1) == SEPARATOR) {
            to--;
        }
        return out.substring(from, to);
    }

    /**
     * Whether one capability covers an action, in any spelling of either.
     * {@code covers("users:*", "USERS.DELETE")} is true;
     * {@code covers("invoices:*", "invoices")} and
     * {@code covers("invoices:read", "invoices-read")} are false.
     */
    public static boolean covers(String capability, String action) {
        String cap = normalize(capability);
        String act = normalize(action);
        if (cap.isEmpty() || act.isEmpty()) {
            return false;
        }
        if (cap.equals(WILDCARD) || cap.equals(act)) {
            return true;
        }
        if (cap.endsWith(":*")) {
            return act.startsWith(cap.substring(0, cap.length() - 1));
        }
        return false;
    }

    /** Whether any capability in the collection covers the action. Null entries are ignored. */
    public static boolean anyCovers(Collection<String> capabilities, String action) {
        if (capabilities == null) {
            return false;
        }
        for (String capability : capabilities) {
            if (capability != null && covers(capability, action)) {
                return true;
            }
        }
        return false;
    }

    /** PHP's trim() default set: space, tab, LF, CR, NUL, vertical tab. */
    private static boolean isTrimmed(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\0' || c == '\u000B';
    }
}
