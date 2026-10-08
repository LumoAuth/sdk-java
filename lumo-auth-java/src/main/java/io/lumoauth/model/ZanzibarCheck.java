package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** The result of a relationship check. */
public record ZanzibarCheck(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("object") String object,
    @JsonProperty("relation") String relation,
    @JsonProperty("subject") String subject
) {
}
