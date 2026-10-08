package io.lumoauth.aauth;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Optional;

/** A JSON Web Key Set, as published at a {@code jwks_uri}. */
public record Jwks(@JsonProperty("keys") List<Jwk> keys) {

    public Jwks {
        keys = keys == null ? List.of() : List.copyOf(keys);
    }

    public static Jwks of(Jwk... jwks) {
        return new Jwks(List.of(jwks));
    }

    /** The key with the given kid. */
    public Optional<Jwk> find(String kid) {
        return keys.stream().filter(k -> kid != null && kid.equals(k.kid())).findFirst();
    }
}
