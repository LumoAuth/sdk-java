package io.lumoauth.spring;

import io.lumoauth.LumoAuth;
import org.springframework.boot.actuate.autoconfigure.health.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/** Registers {@link LumoAuthHealthIndicator} when Spring Boot Actuator is present. */
@AutoConfiguration(after = LumoAuthAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
@ConditionalOnBean(LumoAuth.class)
@ConditionalOnEnabledHealthIndicator("lumoauth")
public class LumoAuthHealthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "lumoauthHealthIndicator")
    public LumoAuthHealthIndicator lumoauthHealthIndicator(LumoAuth lumo) {
        return new LumoAuthHealthIndicator(lumo);
    }
}
