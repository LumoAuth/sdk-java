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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Attribute-based access control: policy evaluation from user, resource and
 * environment attributes, plus attribute management. ABAC is org-scoped, so the
 * client needs an org ID.
 *
 * <p>A user access token needs the {@code abac:read} scope for checks and attribute reads and
 * {@code abac:write} for setting attributes. Organization API keys are not accepted on these routes.
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

    /**
     * Evaluates up to {@link #MAX_BULK_REQUESTS} pairs in one round trip, in request order.
     *
     * <p>The server applies one environment to every check in a bulk call. This form sends the
     * {@code context} that the checks carry: every check must carry the same context (or none),
     * otherwise it throws {@link LumoAuthValidationException}. Use
     * {@link #checkBulk(List, Map)} to pass the shared environment explicitly.
     * Each decision's {@code raw()} keeps the server's {@code index} and any per-item {@code error}.
     */
    public List<AbacDecision> checkBulk(List<AbacCheck> checks) {
        Map<String, Object> shared = null;
        if (checks != null) {
            for (int i = 0; i < checks.size(); i++) {
                AbacCheck check = checks.get(i);
                Map<String, Object> context = check == null ? Map.of() : check.context();
                if (shared == null) {
                    shared = context;
                } else if (!shared.equals(context)) {
                    throw new LumoAuthValidationException("check " + i + " carries a different context: "
                        + "the server applies one environment to every check in a bulk call; "
                        + "pass it with checkBulk(checks, environment)");
                }
            }
        }
        return checkBulk(checks, shared);
    }

    /**
     * Evaluates up to {@link #MAX_BULK_REQUESTS} pairs under one shared {@code environment}.
     * A {@code context} on an individual check is ignored here; the server never reads one per check.
     */
    public List<AbacDecision> checkBulk(List<AbacCheck> checks, Map<String, Object> environment) {
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
                requests.add(checks.get(i).toBulkEntry());
            } catch (LumoAuthValidationException e) {
                throw new LumoAuthValidationException("check " + i + ": " + e.getMessage(), e);
            }
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("checks", requests);
        if (environment != null && !environment.isEmpty()) {
            body.put("environment", environment);
        }
        JsonNode node = http.callNode(Routes.ABAC_CHECK_BULK, null, ApiRequest.json(body));
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
