package io.lumoauth;

/** SDK version and the default User-Agent. */
public final class Version {

    /** The SDK version reported in the User-Agent header. */
    public static final String SDK = "0.1.0";

    private Version() {
    }

    /** {@code lumoauth-java/<version> (Java <runtime version>)}. */
    public static String userAgent() {
        return "lumoauth-java/" + SDK + " (Java " + System.getProperty("java.version", "?") + ")";
    }
}
