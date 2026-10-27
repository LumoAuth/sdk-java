package io.lumoauth.spring;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Optional;

/**
 * Reads the access token of an OIDC browser login ({@link OAuth2AuthenticationToken}) from its
 * {@link OAuth2AuthorizedClient}. The token is refreshed with the refresh token when it has expired.
 *
 * <p>It uses the app's {@link OAuth2AuthorizedClientManager} bean when there is one. Otherwise it builds a
 * manager from the {@link OAuth2AuthorizedClientRepository} (inside a servlet request) or the
 * {@link OAuth2AuthorizedClientService} (outside one). Both managers refresh expired tokens.
 * When no usable token is found, the result is empty, and the caller denies the check.
 */
public class OAuth2AuthorizedClientAccessTokenResolver implements UserAccessTokenResolver {

    private static final Log log = LogFactory.getLog(OAuth2AuthorizedClientAccessTokenResolver.class);

    private final ObjectProvider<OAuth2AuthorizedClientManager> managers;
    private final ObjectProvider<ClientRegistrationRepository> registrations;
    private final ObjectProvider<OAuth2AuthorizedClientRepository> repositories;
    private final ObjectProvider<OAuth2AuthorizedClientService> services;

    public OAuth2AuthorizedClientAccessTokenResolver(ObjectProvider<OAuth2AuthorizedClientManager> managers,
                                                     ObjectProvider<ClientRegistrationRepository> registrations,
                                                     ObjectProvider<OAuth2AuthorizedClientRepository> repositories,
                                                     ObjectProvider<OAuth2AuthorizedClientService> services) {
        this.managers = managers;
        this.registrations = registrations;
        this.repositories = repositories;
        this.services = services;
    }

    @Override
    public Optional<String> resolve(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken login)) {
            return Optional.empty();
        }
        OAuth2AuthorizedClientManager manager = manager();
        if (manager == null) {
            log.debug("No OAuth2AuthorizedClientManager could be built (no ClientRegistrationRepository, "
                + "OAuth2AuthorizedClientRepository or OAuth2AuthorizedClientService bean)");
            return Optional.empty();
        }
        OAuth2AuthorizedClient client;
        try {
            client = manager.authorize(OAuth2AuthorizeRequest
                .withClientRegistrationId(login.getAuthorizedClientRegistrationId())
                .principal(login)
                .build());
        } catch (OAuth2AuthorizationException | IllegalArgumentException e) {
            log.debug("Could not obtain the access token of the OIDC login '"
                + login.getAuthorizedClientRegistrationId() + "': " + e.getMessage());
            return Optional.empty();
        }
        if (client == null || client.getAccessToken() == null) {
            log.debug("The OIDC login '" + login.getAuthorizedClientRegistrationId() + "' has no authorized client");
            return Optional.empty();
        }
        OAuth2AccessToken token = client.getAccessToken();
        if (token.getExpiresAt() != null && token.getExpiresAt().isBefore(Instant.now())) {
            log.debug("The access token of the OIDC login '" + login.getAuthorizedClientRegistrationId()
                + "' has expired and could not be refreshed");
            return Optional.empty();
        }
        return Optional.ofNullable(token.getTokenValue()).filter(v -> !v.isBlank());
    }

    private OAuth2AuthorizedClientManager manager() {
        OAuth2AuthorizedClientManager own = managers.getIfAvailable();
        if (own != null) {
            return own;
        }
        ClientRegistrationRepository clientRegistrations = registrations.getIfAvailable();
        if (clientRegistrations == null) {
            return null;
        }
        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder().refreshToken().build();
        OAuth2AuthorizedClientRepository repository = repositories.getIfAvailable();
        if (repository != null && RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs
            && attrs.getResponse() != null) {
            DefaultOAuth2AuthorizedClientManager manager = new DefaultOAuth2AuthorizedClientManager(clientRegistrations, repository);
            manager.setAuthorizedClientProvider(provider);
            return manager;
        }
        OAuth2AuthorizedClientService service = services.getIfAvailable();
        if (service != null) {
            AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrations, service);
            manager.setAuthorizedClientProvider(provider);
            return manager;
        }
        return null;
    }
}
