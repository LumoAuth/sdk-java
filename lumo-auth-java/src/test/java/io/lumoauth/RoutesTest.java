package io.lumoauth;

import io.lumoauth.errors.LumoAuthConfigException;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoutesTest {

    @Test
    void buildsPathsAndEncodesValues() {
        assertThat(Routes.buildPath("/orgs/{orgId}/api/v1/abac/check", Map.of("orgId", "acme-corp")))
            .isEqualTo("/orgs/acme-corp/api/v1/abac/check");
        assertThat(Routes.path(Routes.ABAC_SET_USER_ATTRIBUTE, Map.of("orgId", "a b", "userId", "u/1", "attributeSlug", "dept")))
            .isEqualTo("/orgs/a%20b/api/v1/abac/users/u%2F1/attributes/dept");
    }

    @Test
    void missingParameterIsAConfigError() {
        assertThatThrownBy(() -> Routes.path(Routes.JIT_COMPLETE_TASK, Map.of("orgId", "acme")))
            .isInstanceOf(LumoAuthConfigException.class)
            .hasMessageContaining("taskId");
        assertThatThrownBy(() -> Routes.get("nope.route")).isInstanceOf(LumoAuthConfigException.class);
    }

    @Test
    void registryIsSortedAndComplete() {
        assertThat(Routes.names()).hasSize(41).containsExactlyElementsOf(new java.util.TreeSet<>(Routes.names()));
        assertThat(Routes.get(Routes.PERMISSIONS_CHECK)).isEqualTo(new Routes.Route("POST", "/api/v1/authz/check"));
    }
}
