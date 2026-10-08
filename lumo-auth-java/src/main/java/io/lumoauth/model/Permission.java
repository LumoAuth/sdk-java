package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** One permission granted to a principal. */
public record Permission(
    @JsonProperty("slug") String slug,
    @JsonProperty("description") String description,
    @JsonProperty("source") String source
) {
}
