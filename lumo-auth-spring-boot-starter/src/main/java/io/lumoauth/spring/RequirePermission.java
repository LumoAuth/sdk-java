package io.lumoauth.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Guards a bean method with a LumoAuth RBAC check for the signed-in principal:
 *
 * <pre>{@code
 * @RequirePermission("document.edit")
 * public void edit(String id) { ... }
 *
 * @RequirePermission(value = {"document.edit", "document.publish"}, mode = RequirePermission.Mode.ANY)
 * public void publish(String id) { ... }
 * }</pre>
 *
 * A missing permission raises Spring Security's {@code AccessDeniedException}
 * (a 403 in web apps); no signed-in principal raises
 * {@code AuthenticationCredentialsNotFoundException} (a 401). The check runs
 * server-side through the {@link LumoAuthorization} bean, so it is also usable
 * from SpEL as {@code @PreAuthorize("@lumo.can('document.edit')")}.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequirePermission {

    /** The permission slugs. */
    String[] value();

    /** Whether every slug is required or any one suffices. */
    Mode mode() default Mode.ALL;

    enum Mode {
        ALL, ANY
    }
}
