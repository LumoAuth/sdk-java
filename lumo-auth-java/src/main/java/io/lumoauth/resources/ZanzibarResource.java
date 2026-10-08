package io.lumoauth.resources;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.internal.Json;
import io.lumoauth.model.ZanzibarCheck;
import io.lumoauth.model.ZanzibarUsersetNode;

import java.util.Map;

/**
 * Google-Zanzibar-style relationship-based access control: does a subject
 * have a relation to an object?
 *
 * <p>Objects and subjects are {@code namespace:id} tuples ("document:readme",
 * "user:alice"), and subjects may name a relation ("group:eng#member").
 *
 * <pre>{@code
 * boolean ok = lumo.zanzibar().check("document:readme", "viewer", "user:bob");
 * boolean ok = lumo.zanzibar().isEditor("document:readme", "user:bob");
 * }</pre>
 */
public final class ZanzibarResource {

    public static final String RELATION_VIEWER = "viewer";
    public static final String RELATION_EDITOR = "editor";
    public static final String RELATION_OWNER = "owner";
    public static final String RELATION_MEMBER = "member";
    public static final String RELATION_ADMIN = "admin";

    private final HttpTransport http;

    public ZanzibarResource(HttpTransport http) {
        this.http = http;
    }

    /** Whether the relationship holds, directly or by inheritance. */
    public boolean check(String object, String relation, String subject) {
        return checkDetailed(object, relation, subject).allowed();
    }

    public ZanzibarCheck checkDetailed(String object, String relation, String subject) {
        validateObjectRelation(object, relation);
        if (subject == null || !subject.contains(":")) {
            throw new LumoAuthValidationException(
                "subject must be in \"namespace:id\" or \"namespace:id#relation\" format");
        }
        Map<String, Object> body = Map.of("object", object, "relation", relation, "subject", subject);
        return http.call(Routes.ZANZIBAR_CHECK, null, ApiRequest.json(body), ZanzibarCheck.class);
    }

    /**
     * The full userset tree for {@code object#relation}: every subject that
     * satisfies the relation, including those reached through namespace rewrites.
     *
     * <p>Expansion always reveals other subjects, so the server requires the
     * oracle privilege (the {@code authz.check} permission or the {@code authz:check}
     * scope); a token that can only check itself gets a 403.
     */
    public ZanzibarUsersetNode expand(String object, String relation) {
        validateObjectRelation(object, relation);
        JsonNode node = http.callNode(Routes.ZANZIBAR_EXPAND, null,
            ApiRequest.json(Map.of("object", object, "relation", relation)));
        JsonNode tree = node == null ? null : node.get("tree");
        if (tree == null || tree.isNull()) {
            throw new LumoAuthValidationException("unexpected response from LumoAuth API: missing \"tree\"");
        }
        return Json.convert(tree, ZanzibarUsersetNode.class, "zanzibar.expand");
    }

    public boolean isViewer(String object, String subject) {
        return check(object, RELATION_VIEWER, subject);
    }

    public boolean isEditor(String object, String subject) {
        return check(object, RELATION_EDITOR, subject);
    }

    public boolean isOwner(String object, String subject) {
        return check(object, RELATION_OWNER, subject);
    }

    public boolean isMember(String object, String subject) {
        return check(object, RELATION_MEMBER, subject);
    }

    public boolean isAdmin(String object, String subject) {
        return check(object, RELATION_ADMIN, subject);
    }

    private static void validateObjectRelation(String object, String relation) {
        if (object == null || !object.contains(":")) {
            throw new LumoAuthValidationException("object must be in \"namespace:id\" format (e.g. \"document:123\")");
        }
        if (relation == null || relation.isBlank()) {
            throw new LumoAuthValidationException("relation is required (e.g. \"viewer\", \"editor\", \"owner\")");
        }
    }
}
