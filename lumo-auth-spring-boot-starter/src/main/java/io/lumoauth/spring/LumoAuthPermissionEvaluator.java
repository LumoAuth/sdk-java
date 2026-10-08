package io.lumoauth.spring;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;

/**
 * Backs {@code hasPermission(...)} in {@code @PreAuthorize} with LumoAuth:
 * <ul>
 *   <li>{@code hasPermission(null, 'document.edit')}: an RBAC check;</li>
 *   <li>{@code hasPermission('document:123', 'viewer')}: a Zanzibar relation check when the
 *       target is a {@code namespace:id} string;</li>
 *   <li>{@code hasPermission(#id, 'document', 'read')}: an ABAC check (target id, type, action).</li>
 * </ul>
 */
public class LumoAuthPermissionEvaluator implements PermissionEvaluator {

    private final LumoAuthorization authorization;

    public LumoAuthPermissionEvaluator(LumoAuthorization authorization) {
        this.authorization = authorization;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (!(permission instanceof String slug)) {
            return false;
        }
        if (targetDomainObject instanceof String object && object.contains(":")) {
            return authorization.relation(object, slug);
        }
        return authorization.can(slug);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (!(permission instanceof String action)) {
            return false;
        }
        return authorization.abac(targetType, action, targetId == null ? null : String.valueOf(targetId));
    }
}
