package io.lumoauth.support;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** Locates {@code sdk-contract/} (a sibling of sdk-java in the umbrella checkout, or {@code LUMO_SDK_CONTRACT}). */
public final class ContractFiles {

    private ContractFiles() {
    }

    public static Optional<Path> dir() {
        String env = System.getenv("LUMO_SDK_CONTRACT");
        Path[] candidates = {
            env == null || env.isBlank() ? null : Path.of(env),
            Path.of("..", "..", "sdk-contract").toAbsolutePath().normalize(),
            Path.of("..", "sdk-contract").toAbsolutePath().normalize(),
        };
        for (Path candidate : candidates) {
            if (candidate != null && Files.isRegularFile(candidate.resolve("routes.json"))) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    public static JsonNode load(String file) {
        Path dir = dir().orElseThrow(() -> new IllegalStateException("sdk-contract not found"));
        try {
            return Json.parse(Files.readAllBytes(dir.resolve(file)), file);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
