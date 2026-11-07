package io.lumoauth;

import java.util.Collection;

/**
 * Agent capability matching, exactly as the LumoAuth server does it.
 *
 * <p>The server stores every capability in one form and matches it with two
 * wildcards, so comparing capability strings with {@code equals} gets both
 * wrong: {@code tool:search_web} is stored as {@code tool.search_web}, and
 * {@code invoices.*} covers {@code invoices.read}.
 *
 * <ul>
 *   <li><b>Stored form.</b> Trimmed, ASCII letters lower-cased, {@code :} and
 *       {@code -} turned into {@code .}, runs of {@code .} collapsed, {@code .}
 *       trimmed from both ends.</li>
 *   <li><b>Wildcards.</b> {@code *} covers every action. A name that ends in
 *       {@code .*} covers every action under that prefix, at any depth, but not
 *       the prefix itself: {@code invoices.*} covers {@code invoices.read},
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

    private Capabilities() {
    }

    /**
     * Returns a capability in the form that the server stores it:
     * {@code "Invoices:Read"} and {@code "invoices-read"} both become
     * {@code "invoices.read"}. Only ASCII letters are lower-cased, as on the server.
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
        boolean lastDot = false;
        for (int i = start; i < end; i++) {
            char c = capability.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + ('a' - 'A'));
            } else if (c == ':' || c == '-') {
                c = '.';
            }
            if (c == '.') {
                if (lastDot) {
                    continue;
                }
                lastDot = true;
            } else {
                lastDot = false;
            }
            out.append(c);
        }
        int from = 0;
        int to = out.length();
        while (from < to && out.charAt(from) == '.') {
            from++;
        }
        while (to > from && out.charAt(to - 1) == '.') {
            to--;
        }
        return out.substring(from, to);
    }

    /**
     * Whether one capability covers an action, in any spelling of either.
     * {@code covers("users:*", "USERS-DELETE")} is true;
     * {@code covers("invoices.*", "invoices")} is false.
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
        if (cap.endsWith(".*")) {
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
