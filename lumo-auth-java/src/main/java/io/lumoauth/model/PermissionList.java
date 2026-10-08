package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** The full set of permissions granted to a principal. */
public record PermissionList(
    @JsonProperty("user_id") String userId,
    @JsonProperty("permissions") List<Permission> permissions,
    @JsonProperty("count") int count
) {
    public PermissionList {
        permissions = Models.list(permissions);
    }

    /** Just the slugs. */
    public List<String> slugs() {
        return permissions.stream().map(Permission::slug).filter(s -> s != null && !s.isEmpty()).toList();
    }
}
