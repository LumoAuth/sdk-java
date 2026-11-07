package io.lumoauth;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.support.ContractFiles;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Capability matching must answer exactly as the server does. The contract cases
 * ({@code sdk-contract/vectors/agent-capabilities.json}) are checked against the
 * server's own matcher by the contract repo, and against this SDK here. The inline
 * cases run even without the contract checkout.
 */
class CapabilitiesTest {

    @Test
    void contractVector() {
        assumeTrue(ContractFiles.dir().isPresent(), "sdk-contract not found (set LUMO_SDK_CONTRACT)");
        JsonNode v = ContractFiles.load("vectors/agent-capabilities.json");
        assertThat(v.get("normalize")).isNotEmpty();
        for (JsonNode c : v.get("normalize")) {
            assertThat(Capabilities.normalize(c.get("input").asText()))
                .as("normalize(%s)", c.get("input")).isEqualTo(c.get("expected").asText());
        }
        for (JsonNode c : v.get("covers")) {
            assertThat(Capabilities.covers(c.get("capability").asText(), c.get("action").asText()))
                .as("covers(%s, %s)", c.get("capability"), c.get("action")).isEqualTo(c.get("expected").asBoolean());
        }
        for (JsonNode c : v.get("any_covers")) {
            List<String> list = new ArrayList<>();
            c.get("capabilities").forEach(n -> list.add(n.asText()));
            assertThat(Capabilities.anyCovers(list, c.get("action").asText()))
                .as("anyCovers(%s, %s)", list, c.get("action")).isEqualTo(c.get("expected").asBoolean());
        }
    }

    @Test
    void inlineRules() {
        assertThat(Capabilities.normalize(" Tool:Search-Web ")).isEqualTo("tool.search.web");
        assertThat(Capabilities.normalize("Ünits.Read")).isEqualTo("Ünits.read"); // ASCII only, as PHP strtolower
        assertThat(Capabilities.normalize(null)).isEmpty();
        assertThat(Capabilities.covers("tool:search_web", "tool.search_web")).isTrue();
        assertThat(Capabilities.covers("invoices.*", "invoices.read.draft")).isTrue();
        assertThat(Capabilities.covers("invoices.*", "invoices")).isFalse();
        assertThat(Capabilities.covers("*.read", "invoices.read")).isFalse();
        assertThat(Capabilities.covers("*", "")).isFalse();
        assertThat(Capabilities.anyCovers(Arrays.asList(null, "users.view"), "users:view")).isTrue();
        assertThat(Capabilities.anyCovers(List.of(), "users.view")).isFalse();
        assertThat(Capabilities.anyCovers(null, "users.view")).isFalse();
    }
}
