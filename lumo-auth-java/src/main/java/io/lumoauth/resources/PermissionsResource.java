package io.lumoauth.resources;

import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.model.CheckOptions;
import io.lumoauth.model.PermissionBulkCheck;
import io.lumoauth.model.PermissionCheck;
import io.lumoauth.model.PermissionList;
import io.lumoauth.model.PermissionMultiCheck;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * RBAC permission checks for the authenticated principal: single checks, bulk
 * checks, logical combinations, and listing.
 *
 * <p>The endpoints infer the organization from the credential, so this
 * namespace works without an org ID.
 *
 * <pre>{@code
 * boolean ok = lumo.permissions().check("document.edit");
 * boolean ok = lumo.permissions().check("document.edit", CheckOptions.forUser(userId));
 * }</pre>
 */
public final class PermissionsResource {

    private final HttpTransport http;

    public PermissionsResource(HttpTransport http) {
        this.http = http;
    }

    /** Whether the principal holds a permission. */
    public boolean check(String permission) {
        return check(permission, CheckOptions.NONE);
    }

    public boolean check(String permission, CheckOptions options) {
        return checkDetailed(permission, options).allowed();
    }

    /** {@link #check} with the full response: the slug, the principal evaluated, the context echoed back. */
    public PermissionCheck checkDetailed(String permission, CheckOptions options) {
        if (permission == null || permission.isBlank()) {
            throw new LumoAuthValidationException("a permission slug is required");
        }
        Map<String, Object> body = checkBody(options);
        body.put("permission", permission);
        return http.call(Routes.PERMISSIONS_CHECK, null, ApiRequest.json(body), PermissionCheck.class);
    }

    /** Evaluates many permissions in one round trip; one decision per requested slug. */
    public PermissionBulkCheck checkBulk(List<String> permissions) {
        return checkBulk(permissions, CheckOptions.NONE);
    }

    public PermissionBulkCheck checkBulk(List<String> permissions, CheckOptions options) {
        requirePermissions(permissions);
        Map<String, Object> body = checkBody(options);
        body.put("permissions", permissions);
        return http.call(Routes.PERMISSIONS_CHECK_BULK, null, ApiRequest.json(body), PermissionBulkCheck.class);
    }

    /** Whether the principal holds at least one of the permissions (logical OR). */
    public boolean checkAny(List<String> permissions) {
        return checkAny(permissions, CheckOptions.NONE);
    }

    public boolean checkAny(List<String> permissions, CheckOptions options) {
        return checkAnyDetailed(permissions, options).allowed();
    }

    public PermissionMultiCheck checkAnyDetailed(List<String> permissions, CheckOptions options) {
        return multiCheck(Routes.PERMISSIONS_CHECK_ANY, permissions, options);
    }

    /** Whether the principal holds every one of the permissions (logical AND). */
    public boolean checkAll(List<String> permissions) {
        return checkAll(permissions, CheckOptions.NONE);
    }

    public boolean checkAll(List<String> permissions, CheckOptions options) {
        return checkAllDetailed(permissions, options).allowed();
    }

    public PermissionMultiCheck checkAllDetailed(List<String> permissions, CheckOptions options) {
        return multiCheck(Routes.PERMISSIONS_CHECK_ALL, permissions, options);
    }

    /** Every permission granted to the authenticated principal. */
    public PermissionList list() {
        return http.call(Routes.PERMISSIONS_LIST, null, null, PermissionList.class);
    }

    /** Just the permission slugs granted to the principal. */
    public List<String> listSlugs() {
        return list().slugs();
    }

    private PermissionMultiCheck multiCheck(String route, List<String> permissions, CheckOptions options) {
        requirePermissions(permissions);
        Map<String, Object> body = checkBody(options);
        body.put("permissions", permissions);
        return http.call(route, null, ApiRequest.json(body), PermissionMultiCheck.class);
    }

    private static void requirePermissions(List<String> permissions) {
        if (permissions == null || permissions.isEmpty()) {
            throw new LumoAuthValidationException("at least one permission is required");
        }
    }

    private static Map<String, Object> checkBody(CheckOptions options) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (options == null) {
            return body;
        }
        if (!options.context().isEmpty()) {
            body.put("context", options.context());
        }
        if (options.userId() != null) {
            body.put("user_id", options.userId());
        }
        return body;
    }
}
