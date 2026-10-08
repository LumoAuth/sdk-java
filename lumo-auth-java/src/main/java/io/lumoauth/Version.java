package io.lumoauth;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * SDK version and the default User-Agent.
 *
 * <p>The version is read from {@code io/lumoauth/version.properties}, which Maven fills in from the
 * POM at build time, so {@code mvn versions:set} is the only place a release bumps it. Outside a
 * Maven build (an IDE that skips resource filtering, a shaded jar missing the resource) it reads
 * {@code 0.0.0-dev}.
 */
public final class Version {

    /** The version reported in the User-Agent header. */
    public static final String SDK = load();

    private static final String UNKNOWN = "0.0.0-dev";

    private Version() {
    }

    /** {@code lumoauth-java/<version> (Java <runtime version>)}. */
    public static String userAgent() {
        return "lumoauth-java/" + SDK + " (Java " + System.getProperty("java.version", "?") + ")";
    }

    private static String load() {
        try (InputStream in = Version.class.getResourceAsStream("/io/lumoauth/version.properties")) {
            if (in == null) {
                return UNKNOWN;
            }
            Properties props = new Properties();
            props.load(in);
            String value = props.getProperty("sdk", "").trim();
            // An unfiltered copy still carries the placeholder.
            return value.isEmpty() || value.startsWith("${") ? UNKNOWN : value;
        } catch (IOException e) {
            return UNKNOWN;
        }
    }
}
