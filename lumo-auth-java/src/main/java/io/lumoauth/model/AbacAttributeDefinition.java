package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * An attribute the organization has defined.
 *
 * @param attributeType user | resource | environment
 * @param dataType      string | number | boolean | array | date
 */
public record AbacAttributeDefinition(
    @JsonProperty("id") String id,
    @JsonProperty("name") String name,
    @JsonProperty("slug") String slug,
    @JsonProperty("description") String description,
    @JsonProperty("attributeType") String attributeType,
    @JsonProperty("dataType") String dataType,
    @JsonProperty("validationRules") Map<String, Object> validationRules,
    @JsonProperty("isActive") boolean active
) {
    public AbacAttributeDefinition {
        validationRules = Models.map(validationRules);
    }
}
