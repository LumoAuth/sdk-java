package io.lumoauth.spring;

import io.lumoauth.LumoAuth;
import io.lumoauth.errors.LumoAuthApiException;
import io.lumoauth.errors.LumoAuthException;
import io.lumoauth.model.UserInfo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves a LumoAuth bearer token to a principal through the userinfo
 * endpoint, for Spring Security's resource-server support
 * ({@code oauth2ResourceServer().opaqueToken()}). The principal's name is the
 * {@code sub} claim, its attributes are every userinfo claim, and its
 * authorities are {@code ROLE_<role>} for each role, {@code CAPABILITY_<slug>}
 * for each agent capability and, when enabled, {@code PERMISSION_<slug>} for
 * each granted permission.
 */
public class LumoAuthTokenIntrospector implements OpaqueTokenIntrospector {

    private final LumoAuth lumo;
    private final LumoAuthProperties.Security settings;

    public LumoAuthTokenIntrospector(LumoAuth lumo, LumoAuthProperties.Security settings) {
        this.lumo = lumo;
        this.settings = settings;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        UserInfo info;
        try {
            info = lumo.auth().userinfo(token);
        } catch (LumoAuthApiException e) {
            if (e.statusCode() == 401 || e.statusCode() == 403) {
                throw new BadOpaqueTokenException("LumoAuth rejected the access token: " + e.getMessage(), e);
            }
            throw new OAuth2IntrospectionException("LumoAuth userinfo failed: " + e.getMessage(), e);
        } catch (LumoAuthException e) {
            throw new OAuth2IntrospectionException("LumoAuth is unreachable: " + e.getMessage(), e);
        }
        if (info == null || info.sub() == null || info.sub().isBlank()) {
            throw new BadOpaqueTokenException("userinfo has no sub claim");
        }
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : info.roles()) {
            authorities.add(new SimpleGrantedAuthority(settings.getRoleAuthorityPrefix() + role));
        }
        for (String capability : info.capabilities()) {
            authorities.add(new SimpleGrantedAuthority(settings.getCapabilityAuthorityPrefix() + capability));
        }
        if (settings.isPermissionsAsAuthorities()) {
            LumoAuth asUser = LumoAuth.builder().baseUrl(lumo.baseUrl()).orgId(lumo.orgId().orElse(null))
                .apiKey(null).accessToken(token)
                .httpClient(lumo.transport().httpClient()).timeout(lumo.transport().timeout()).build();
            for (String slug : asUser.permissions().listSlugs()) {
                authorities.add(new SimpleGrantedAuthority(settings.getPermissionAuthorityPrefix() + slug));
            }
        }
        Map<String, Object> attributes = new LinkedHashMap<>(info.raw());
        attributes.putIfAbsent("sub", info.sub());
        return new OAuth2IntrospectionAuthenticatedPrincipal(info.sub(), attributes, authorities);
    }
}
