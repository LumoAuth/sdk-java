package io.lumoauth.spring;

import io.lumoauth.spring.support.FakeServer;
import io.lumoauth.spring.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LumoAuthHealthIndicatorTest {

    private final FakeServer server = new FakeServer();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(LumoAuthAutoConfiguration.class, LumoAuthHealthAutoConfiguration.class))
        .withPropertyValues("lumoauth.url=" + server.url(), "lumoauth.org-id=acme");

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void reportsUpWithTheIssuer() {
        server.on("/orgs/acme/api/v1/.well-known/openid-configuration", Reply.json(Map.of("issuer", server.url() + "/orgs/acme/api/v1")));
        runner.run(context -> {
            assertThat(context).hasBean("lumoauthHealthIndicator");
            Health health = context.getBean("lumoauthHealthIndicator", HealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.UP);
            assertThat(health.getDetails()).containsEntry("orgId", "acme").containsEntry("issuer", server.url() + "/orgs/acme/api/v1");
        });
    }

    @Test
    void reportsDownOnFailure() {
        server.on("/orgs/acme/api/v1/.well-known/openid-configuration", Reply.json(503, Map.of("error", "maintenance")));
        runner.run(context -> {
            Health health = context.getBean("lumoauthHealthIndicator", HealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.DOWN);
            assertThat(health.getDetails()).containsEntry("code", "maintenance").containsKey("error");
        });
        runner.withPropertyValues("management.health.lumoauth.enabled=false").run(context ->
            assertThat(context).doesNotHaveBean("lumoauthHealthIndicator"));
    }
}
