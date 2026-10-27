package io.lumoauth.spring;

import io.lumoauth.LumoAuth;
import io.lumoauth.errors.LumoAuthException;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;

import java.util.Map;

/**
 * Reports whether the configured LumoAuth instance answers, under
 * {@code /actuator/health/lumoauth}: it fetches the organization's OpenID
 * discovery document (or the instance-root AAuth issuer document when no org
 * is configured) and reports UP with the issuer on 200.
 */
public class LumoAuthHealthIndicator extends AbstractHealthIndicator {

    private final LumoAuth lumo;

    public LumoAuthHealthIndicator(LumoAuth lumo) {
        super("LumoAuth health check failed");
        this.lumo = lumo;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        String path = lumo.orgId().map(org -> lumo.orgPath("/.well-known/openid-configuration"))
            .orElse("/.well-known/aauth-issuer");
        try {
            Map<String, Object> document = lumo.requestMap("GET", path, null);
            builder.up()
                .withDetail("url", lumo.baseUrl())
                .withDetail("issuer", document.getOrDefault("issuer", lumo.baseUrl()));
            lumo.orgId().ifPresent(org -> builder.withDetail("orgId", org));
        } catch (LumoAuthException e) {
            builder.down(e).withDetail("url", lumo.baseUrl()).withDetail("code", e.code());
        }
    }
}
