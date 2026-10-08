package io.lumoauth.model;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Small helpers shared by the model records. */
public final class Models {

    private Models() {
    }

    /** An unmodifiable copy, or an empty list for null. Null elements are kept. */
    public static <T> List<T> list(List<T> in) {
        return in == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(in));
    }

    /** An unmodifiable copy, or an empty map for null. Null values are kept. */
    public static <K, V> Map<K, V> map(Map<K, V> in) {
        return in == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(in));
    }

    /** Null for blank strings, so {@code Optional.ofNullable} works on wire values. */
    public static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /** Parses an ISO-8601 timestamp (with offset or {@code Z}) the server sent. */
    public static Optional<Instant> parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(OffsetDateTime.parse(value).toInstant());
        } catch (DateTimeParseException e) {
            try {
                return Optional.of(Instant.parse(value));
            } catch (DateTimeParseException ignored) {
                return Optional.empty();
            }
        }
    }

    /** Splits a space-separated OAuth scope string, dropping empties. */
    public static List<String> splitScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }
        return List.of(scope.trim().split("\\s+"));
    }

    /** Renders scopes for the wire. */
    public static String joinScopes(List<String> scopes) {
        return scopes == null ? "" : String.join(" ", scopes);
    }
}
