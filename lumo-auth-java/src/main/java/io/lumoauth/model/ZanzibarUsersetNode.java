package io.lumoauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * A node in a Zanzibar expansion tree. Leaves carry {@link #subjects()};
 * union/intersection nodes carry {@link #children()} of the same shape.
 *
 * @param type "union", "intersection" or "leaf"
 */
public record ZanzibarUsersetNode(
    @JsonProperty("type") String type,
    @JsonProperty("object") String object,
    @JsonProperty("relation") String relation,
    @JsonProperty("children") List<ZanzibarUsersetNode> children,
    @JsonProperty("subjects") List<String> subjects
) {
    public ZanzibarUsersetNode {
        children = Models.list(children);
        subjects = Models.list(subjects);
    }

    /** Every subject in the tree, depth-first, without duplicates. */
    public List<String> allSubjects() {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>(subjects);
        for (ZanzibarUsersetNode child : children) {
            out.addAll(child.allSubjects());
        }
        return List.copyOf(out);
    }
}
