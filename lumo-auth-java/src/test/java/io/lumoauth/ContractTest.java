package io.lumoauth;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.errors.ErrorCodes;
import io.lumoauth.support.ContractFiles;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Conformance against the cross-SDK contract ({@code ../../sdk-contract}):
 * every registered route exists in routes.json with the same method; every
 * contract route in a claimed namespace is registered (or allowlisted); every
 * error code in errors.json has an {@link ErrorCodes} constant. Skips when the
 * contract is not checked out next to sdk-java.
 */
class ContractTest {

    @BeforeAll
    static void requireContract() {
        assumeTrue(ContractFiles.dir().isPresent(), "sdk-contract not found (set LUMO_SDK_CONTRACT)");
    }

    private static String key(String method, String path) {
        return method + " " + path.replaceAll("\\{[^}]+\\}", "{}");
    }

    @Test
    void everyRegisteredRouteIsInTheContract() {
        JsonNode contract = ContractFiles.load("routes.json");
        Map<String, JsonNode> known = new HashMap<>();
        for (JsonNode route : contract.get("routes")) {
            known.put(key(route.get("method").asText(), route.get("path").asText()), route);
        }
        Routes.all().forEach((name, route) -> {
            assertThat(known).as("%s (%s %s) is in routes.json", name, route.method(), route.path())
                .containsKey(key(route.method(), route.path()));
            assertThat(known.get(key(route.method(), route.path())).get("name").asText())
                .as("canonical name of %s", name).isEqualTo(name);
        });
    }

    @Test
    void everyClaimedContractRouteIsRegistered() {
        JsonNode contract = ContractFiles.load("routes.json");
        JsonNode me = ContractFiles.load("features.json").get("sdks").get("java");
        assertThat(me).as("features.json has a 'java' entry").isNotNull();
        Set<String> claimed = new HashSet<>();
        me.get("namespaces").forEach(n -> claimed.add(n.asText()));
        JsonNode allowed = me.get("known_missing_routes");
        Set<String> have = new HashSet<>();
        Routes.all().values().forEach(r -> have.add(key(r.method(), r.path())));
        for (JsonNode route : contract.get("routes")) {
            if (!claimed.contains(route.get("namespace").asText())) {
                continue;
            }
            String name = route.get("name").asText();
            boolean present = have.contains(key(route.get("method").asText(), route.get("path").asText()));
            if (allowed != null && allowed.has(name)) {
                assertThat(present).as("%s is listed in known_missing_routes but Routes has it", name).isFalse();
                continue;
            }
            assertThat(present).as("contract route %s is registered", name).isTrue();
        }
    }

    @Test
    void everyContractErrorCodeHasAConstant() throws IllegalAccessException {
        Set<String> codes = new HashSet<>();
        for (Field field : ErrorCodes.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                codes.add((String) field.get(null));
            }
        }
        JsonNode errors = ContractFiles.load("errors.json").get("errors");
        for (JsonNode error : errors) {
            assertThat(codes).as("%s has an ErrorCodes constant", error.get("name").asText())
                .contains(error.get("code").asText());
            assertThat(error.get("java")).as("%s names its Java class", error.get("name").asText()).isNotNull();
            String className = "io.lumoauth.errors." + error.get("java").asText();
            assertThat(classExists(className)).as("%s exists", className).isTrue();
        }
        assertThat(codes).hasSize(errors.size());
    }

    @Test
    void sdkVersionMatchesFeatures() {
        JsonNode me = ContractFiles.load("features.json").get("sdks").get("java");
        assertThat(me.get("version").asText()).isEqualTo(Version.SDK);
    }

    private static boolean classExists(String name) {
        try {
            Class.forName(name);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
