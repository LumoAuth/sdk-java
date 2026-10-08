package io.lumoauth.resources;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.internal.Json;
import io.lumoauth.model.AbacAttributeDefinition;
import io.lumoauth.model.AbacCheck;
import io.lumoauth.model.AbacDecision;
import io.lumoauth.model.AttributeType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Attribute-based access control: policy evaluation from user, resource and
 * environment attributes, plus attribute management. ABAC is org-scoped, so the
 * client needs an org ID.
 *
 * <pre>{@code
 * AbacDecision decision = lumo.abac().check(AbacCheck.of("document", "read", "doc-123"));
 * }</pre>
 */
public final class AbacResource {

    /** The server's cap on one bulk check. */
    public static final int MAX_BULK_REQUESTS = 100;

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };
    private static final TypeReference<List<AbacAttributeDefinition>> DEFINITIONS = new TypeReference<>() {
    };

    private final HttpTransport http;

    public AbacResource(HttpTransport http) {
        this.http = http;
    }

    /** Evaluates the policies for one resource/action pair, returning the full decision. */
    public AbacDecision check(AbacCheck check) {
        return http.call(Routes.ABAC_CHECK, null, ApiRequest.json(check.toBody()), AbacDecision.class);
    }

    /** {@link #check} reduced to a boolean. */
    public boolean isAllowed(AbacCheck check) {
        return check(check).allowed();
    }

    /** Evaluates up to {@link #MAX_BULK_REQUESTS} pairs in one round trip, in request order. */
    public List<AbacDecision> checkBulk(List<AbacCheck> checks) {
        if (checks == null || checks.isEmpty()) {
            throw new LumoAuthValidationException("at least one check request is required");
        }
        if (checks.size() > MAX_BULK_REQUESTS) {
            throw new LumoAuthValidationException(
                "a bulk check accepts at most " + MAX_BULK_REQUESTS + " requests (got " + checks.size() + ")");
        }
        List<Map<String, Object>> requests = new ArrayList<>(checks.size());
        for (int i = 0; i < checks.size(); i++) {
            try {
                requests.add(checks.get(i).toBody());
            } catch (LumoAuthValidationException e) {
                throw new LumoAuthValidationException("check " + i + ": " + e.getMessage(), e);
            }
        }
        JsonNode node = http.callNode(Routes.ABAC_CHECK_BULK, null, ApiRequest.json(Map.of("requests", requests)));
        JsonNode results = node == null ? null : node.get("results");
        List<AbacDecision> out = new ArrayList<>();
        if (results != null && results.isArray()) {
            for (JsonNode item : results) {
                out.add(Json.convert(item, AbacDecision.class, "abac.checkBulk"));
            }
        }
        return List.copyOf(out);
    }

    /** Every ABAC attribute for the authenticated user, built-in and custom. */
    public Map<String, Object> myAttributes() {
        JsonNode node = http.callNode(Routes.ABAC_MY_ATTRIBUTES, null, null);
        return node == null ? Map.of() : Json.convert(node, MAP, "abac.myAttributes");
    }

    /** Sets one attribute value on a user. */
    public void setUserAttribute(String userId, String attributeSlug, Object value) {
        if (isBlank(userId) || isBlank(attributeSlug)) {
            throw new LumoAuthValidationException("userId and attributeSlug are both required");
        }
        Map<String, String> params = Map.of("userId", userId, "attributeSlug", attributeSlug);
        http.callNode(Routes.ABAC_SET_USER_ATTRIBUTE, params, ApiRequest.json(valueBody(value)));
    }

    /** The ABAC attributes attached to one resource. */
    public Map<String, Object> resourceAttributes(String resourceType, String resourceId) {
        if (isBlank(resourceType) || isBlank(resourceId)) {
            throw new LumoAuthValidationException("resourceType and resourceId are both required");
        }
        Map<String, String> params = Map.of("resourceType", resourceType, "resourceId", resourceId);
        JsonNode node = http.callNode(Routes.ABAC_RESOURCE_ATTRIBUTES, params, null);
        return node == null ? Map.of() : Json.convert(node, MAP, "abac.resourceAttributes");
    }

    /** Sets one attribute value on a resource. */
    public void setResourceAttribute(String resourceType, String resourceId, String attributeSlug, Object value) {
        if (isBlank(resourceType) || isBlank(resourceId) || isBlank(attributeSlug)) {
            throw new LumoAuthValidationException("resourceType, resourceId and attributeSlug are all required");
        }
        Map<String, String> params = Map.of(
            "resourceType", resourceType, "resourceId", resourceId, "attributeSlug", attributeSlug);
        http.callNode(Routes.ABAC_SET_RESOURCE_ATTRIBUTE, params, ApiRequest.json(valueBody(value)));
    }

    /** All of the organization's attribute definitions. */
    public List<AbacAttributeDefinition> attributeDefinitions() {
        return attributeDefinitions(null);
    }

    /** The organization's attribute definitions of one type (null for all). */
    public List<AbacAttributeDefinition> attributeDefinitions(AttributeType type) {
        ApiRequest request = ApiRequest.empty();
        if (type != null) {
            request.query("type", type.wire());
        }
        // The endpoint returns either a bare array or an envelope with `data`.
        JsonNode node = http.callNode(Routes.ABAC_ATTRIBUTE_DEFINITIONS, null, request);
        if (node == null) {
            return List.of();
        }
        JsonNode array = node.isArray() ? node : node.get("data");
        if (array == null || !array.isArray()) {
            throw new LumoAuthValidationException("could not decode the attribute definitions response");
        }
        return Json.convert(array, DEFINITIONS, "abac.attributeDefinitions");
    }

    private static Map<String, Object> valueBody(Object value) {
        Map<String, Object> body = new java.util.HashMap<>();
        body.put("value", value);
        return body;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
