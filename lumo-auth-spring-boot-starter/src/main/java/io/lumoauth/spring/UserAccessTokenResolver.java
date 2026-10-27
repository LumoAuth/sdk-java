package io.lumoauth.spring;

import org.springframework.security.core.Authentication;

import java.util.Optional;

/**
 * Finds the signed-in user's LumoAuth access token for an {@link Authentication} that does not carry one
 * itself, such as an OIDC browser login. ABAC checks need this token, because LumoAuth refuses the
 * organization API key on the ABAC routes.
 *
 * <p>With {@code spring-security-oauth2-client} on the classpath, the starter registers
 * {@link OAuth2AuthorizedClientAccessTokenResolver}. Define your own bean of this type to replace it.
 */
@FunctionalInterface
public interface UserAccessTokenResolver {

    /** Never finds a token. */
    UserAccessTokenResolver NONE = authentication -> Optional.empty();

    /** The user's current access token, or empty when none is available. */
    Optional<String> resolve(Authentication authentication);
}
