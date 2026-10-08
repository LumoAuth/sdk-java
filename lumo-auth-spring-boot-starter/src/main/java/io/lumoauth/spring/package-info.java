/**
 * Spring Boot auto-configuration for the LumoAuth Java SDK. Bind
 * {@code lumoauth.*} properties and inject {@link io.lumoauth.LumoAuth},
 * {@link io.lumoauth.LumoAgent} or {@link io.lumoauth.aauth.AAuthClient};
 * guard methods with {@link io.lumoauth.spring.RequirePermission} or
 * {@code @PreAuthorize("@lumo.can('...')")}.
 */
package io.lumoauth.spring;
