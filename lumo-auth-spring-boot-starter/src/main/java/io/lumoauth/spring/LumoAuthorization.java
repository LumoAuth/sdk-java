package io.lumoauth.spring;

import io.lumoauth.LumoAuth;
import io.lumoauth.model.AbacCheck;
import io.lumoauth.model.CheckOptions;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Token;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Authorization checks for the current Spring Security principal, registered
 * as the bean {@code lumo} so they read naturally from SpEL:
 *
 * <pre>{@code
 * @PreAuthorize("@lumo.can('document.edit')")
 * @PreAuthorize("@lumo.canAny('document.edit', 'document.admin')")
 * @PreAuthorize("@lumo.isViewer('document:' + #id)")
 * @PreAuthorize("@lumo.abac('document', 'read', #id)")
 * }</pre>
 *
 * When the principal signed in with a LumoAuth bearer token, checks run under
 * that token, so they need no API key. Otherwise they run with the
 * application's API key on behalf of the principal's name (the {@code sub}).
 */
public class LumoAuthorization {

    private final LumoAuth lumo;

    public LumoAuthorization(LumoAuth lumo) {
        this.lumo = lumo;
    }

    /** Whether the current principal holds a permission. */
    public boolean can(String permission) {
        Principal p = principal();
        return p.client().permissions().check(permission, p.options());
    }

    /** Whether the current principal holds every permission. */
    public boolean canAll(String... permissions) {
        Principal p = principal();
        return p.client().permissions().checkAll(Arrays.asList(permissions), p.options());
    }

    /** Whether the current principal holds at least one permission. */
    public boolean canAny(String... permissions) {
        Principal p = principal();
        return p.client().permissions().checkAny(Arrays.asList(permissions), p.options());
    }

    /** Whether {@code user:<principal>} has a relation to an object ("document:123"). */
    public boolean relation(String object, String relation) {
        Principal p = principal();
        return p.client().zanzibar().check(object, relation, "user:" + p.name());
    }

    public boolean isViewer(String object) {
        return relation(object, "viewer");
    }

    public boolean isEditor(String object) {
        return relation(object, "editor");
    }

    public boolean isOwner(String object) {
        return relation(object, "owner");
    }

    /** An ABAC decision for the current principal. */
    public boolean abac(String resourceType, String action, String resourceId) {
        return principal().client().abac().isAllowed(AbacCheck.of(resourceType, action, resourceId));
    }

    /** {@link #can} / {@link #canAll} / {@link #canAny} for a {@link RequirePermission} declaration. */
    public boolean satisfies(List<String> permissions, RequirePermission.Mode mode) {
        if (permissions.isEmpty()) {
            return true;
        }
        if (permissions.size() == 1) {
            return can(permissions.get(0));
        }
        String[] slugs = permissions.toArray(new String[0]);
        return mode == RequirePermission.Mode.ANY ? canAny(slugs) : canAll(slugs);
    }

    /** The current authenticated principal, or an exception when there is none. */
    public Principal principal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            throw new AuthenticationCredentialsNotFoundException("no authenticated principal for the LumoAuth check");
        }
        Optional<String> bearer = bearerToken(authentication);
        LumoAuth client = bearer.map(token -> LumoAuth.builder()
                .baseUrl(lumo.baseUrl())
                .orgId(lumo.orgId().orElse(null))
                .apiKey(null)
                .accessToken(token)
                .httpClient(lumo.transport().httpClient())
                .timeout(lumo.transport().timeout())
                .build())
            .orElse(lumo);
        return new Principal(authentication.getName(), client, bearer.isEmpty() ? CheckOptions.forUser(authentication.getName()) : CheckOptions.NONE);
    }

    /** The current principal, the client to check with, and the options that scope the check to them. */
    public record Principal(String name, LumoAuth client, CheckOptions options) {
    }

    private static Optional<String> bearerToken(Authentication authentication) {
        Object credentials = authentication.getCredentials();
        if (credentials instanceof OAuth2Token token) {
            return Optional.ofNullable(token.getTokenValue());
        }
        return Optional.empty();
    }
}
