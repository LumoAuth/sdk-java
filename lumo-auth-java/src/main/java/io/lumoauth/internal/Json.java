package io.lumoauth.internal;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.model.RawPayload;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * The SDK's JSON codec. Internal: the configured {@link ObjectMapper} is private
 * to the SDK so an application's own mapper settings can never change what goes
 * on the wire.
 */
public final class Json {

    private static final ObjectMapper MAPPER = JsonMapper.builder()
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
        .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
        .serializationInclusion(JsonInclude.Include.NON_NULL)
        .build();

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private Json() {
    }

    /** Encodes a value as UTF-8 JSON bytes. */
    public static byte[] encode(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new LumoAuthValidationException("could not encode the request body: " + e.getOriginalMessage(), e);
        }
    }

    /** Encodes a value as a JSON string. */
    public static String encodeToString(Object value) {
        return new String(encode(value), StandardCharsets.UTF_8);
    }

    /** Parses JSON bytes into a tree; a syntax error is a validation exception. */
    public static JsonNode parse(byte[] body, String context) {
        try {
            return MAPPER.readTree(body);
        } catch (IOException e) {
            throw new LumoAuthValidationException("could not decode the response from " + context + ": " + e.getMessage(), e);
        }
    }

    /** Parses JSON bytes into a tree, returning {@code null} rather than throwing on malformed input. */
    public static JsonNode tryParse(byte[] body) {
        try {
            return MAPPER.readTree(body);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Converts a tree into a typed value. Types implementing {@link RawPayload}
     * additionally receive the complete decoded object, so fields the SDK does
     * not model yet stay reachable.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public static <T> T convert(JsonNode node, Class<T> type, String context) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        try {
            T value = MAPPER.treeToValue(node, type);
            if (value instanceof RawPayload raw && node.isObject()) {
                value = (T) raw.withRaw(toMap(node));
            }
            return value;
        } catch (IllegalArgumentException | JsonProcessingException e) {
            throw new LumoAuthValidationException("could not decode the response from " + context + ": " + e.getMessage(), e);
        }
    }

    /** Converts a tree into a typed value using a full generic type. */
    public static <T> T convert(JsonNode node, TypeReference<T> type, String context) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        try {
            return MAPPER.convertValue(node, type);
        } catch (IllegalArgumentException e) {
            throw new LumoAuthValidationException("could not decode the response from " + context + ": " + e.getMessage(), e);
        }
    }

    /** A JSON object as a plain map (nested objects become maps, arrays lists). */
    public static Map<String, Object> toMap(JsonNode node) {
        if (node == null || !node.isObject()) {
            return Map.of();
        }
        return MAPPER.convertValue(node, MAP);
    }

    /** Any JSON value as a plain Java value. */
    public static Object toValue(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        return MAPPER.convertValue(node, Object.class);
    }

    /** The shared mapper, for the rare caller that needs Jackson directly. */
    public static ObjectMapper mapper() {
        return MAPPER;
    }
}
