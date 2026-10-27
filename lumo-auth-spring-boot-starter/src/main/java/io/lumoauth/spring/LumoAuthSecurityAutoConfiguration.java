package io.lumoauth.spring;

import io.lumoauth.LumoAuth;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.aop.Advisor;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

/**
 * Spring Security integration:
 * <ul>
 *   <li>{@link LumoAuthTokenIntrospector}: LumoAuth bearer tokens become principals
 *       (Spring Boot's resource-server auto-configuration picks the bean up);</li>
 *   <li>the {@code lumo} SpEL bean ({@link LumoAuthorization}) and a
 *       {@link PermissionEvaluator} for {@code @PreAuthorize};</li>
 *   <li>with the OAuth2 client on the classpath, a {@link UserAccessTokenResolver} that reads an
 *       OIDC login's access token for ABAC checks;</li>
 *   <li>{@link RequirePermission} method guards.</li>
 * </ul>
 */
@AutoConfiguration(after = LumoAuthAutoConfiguration.class,
    beforeName = {
        "org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration"
    })
@ConditionalOnClass(SecurityContextHolder.class)
public class LumoAuthSecurityAutoConfiguration {

    @Bean("lumo")
    @ConditionalOnMissingBean
    public LumoAuthorization lumoAuthorization(LumoAuth lumo, ObjectProvider<UserAccessTokenResolver> userTokens) {
        return new LumoAuthorization(lumo, userTokens.getIfAvailable(() -> UserAccessTokenResolver.NONE));
    }

    /** Finds the access token of an OIDC browser login, for ABAC checks. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager")
    static class OAuth2ClientAccessTokens {
        @Bean
        @ConditionalOnMissingBean(UserAccessTokenResolver.class)
        OAuth2AuthorizedClientAccessTokenResolver lumoAuthUserAccessTokenResolver(
            ObjectProvider<OAuth2AuthorizedClientManager> managers,
            ObjectProvider<ClientRegistrationRepository> registrations,
            ObjectProvider<OAuth2AuthorizedClientRepository> repositories,
            ObjectProvider<OAuth2AuthorizedClientService> services) {
            return new OAuth2AuthorizedClientAccessTokenResolver(managers, registrations, repositories, services);
        }
    }

    @Bean
    @ConditionalOnMissingBean(PermissionEvaluator.class)
    public LumoAuthPermissionEvaluator lumoAuthPermissionEvaluator(LumoAuthorization authorization) {
        return new LumoAuthPermissionEvaluator(authorization);
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnClass(Advisor.class)
    public Advisor lumoAuthRequirePermissionAdvisor(LumoAuthorization authorization) {
        // Methods annotated directly, or any public method of an annotated class.
        ComposablePointcut pointcut = new ComposablePointcut(new AnnotationMatchingPointcut(null, RequirePermission.class, true))
            .union(AnnotationMatchingPointcut.forClassAnnotation(RequirePermission.class));
        return new DefaultPointcutAdvisor(pointcut, new RequirePermissionInterceptor(authorization));
    }

    @Bean
    @ConditionalOnClass(OpaqueTokenIntrospector.class)
    @ConditionalOnMissingBean(OpaqueTokenIntrospector.class)
    @ConditionalOnProperty(prefix = "lumoauth.security", name = "bearer-tokens", havingValue = "true", matchIfMissing = true)
    public LumoAuthTokenIntrospector lumoAuthTokenIntrospector(LumoAuth lumo, LumoAuthProperties props) {
        return new LumoAuthTokenIntrospector(lumo, props.getSecurity());
    }
}
