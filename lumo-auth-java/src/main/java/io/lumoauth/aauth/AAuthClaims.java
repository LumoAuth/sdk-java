package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.model.Models;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The claims carried by a verified {@code auth+jwt}.
 *
 * <p>AAuth auth tokens are proof-of-possession tokens: after verifying the JWT,
 * a resource MUST also call {@link #verifyProofOfPossession} on the incoming
 * request, or a stolen token would be replayable.
 *
 * @param confirmation the key the token is bound to (RFC 7800 {@code cnf.jwk})
 * @param act          the delegation chain, when there is one
 * @param raw          every claim in the token, including ones not modelled here
 */
public record AAuthClaims(String issuer, String audience, long expires, long issuedAt, String jti, String subject,
                          String agent, String agentDelegate, String scope, Jwk confirmation,
                          Map<String, Object> act, Map<String, Object> raw) {

    public AAuthClaims {
        act = Models.map(act);
        raw = Models.map(raw);
    }

    /** The space-separated scope claim, split. */
    public List<String> scopes() {
        return Models.splitScopes(scope);
    }

    public boolean hasScope(String wanted) {
        return scopes().contains(wanted);
    }

    /** Any claim by name. */
    public Optional<Object> claim(String name) {
        return Optional.ofNullable(raw.get(name));
    }

    /**
     * Checks that an incoming request was signed by the key the token is bound
     * to ({@code cnf.jwk}): the second half of AAuth verification.
     * {@code request.body()} must be the exact bytes received, since Content-Digest
     * is computed over them.
     *
     * @throws LumoAuthValidationException when the signature is missing, malformed, or does not verify
     */
    public void verifyProofOfPossession(IncomingRequest request) {
        if (confirmation == null || confirmation.kty() == null) {
            throw new LumoAuthValidationException("the token has no cnf.jwk claim to verify against");
        }
        String signatureInput = request.header("Signature-Input");
        String signatureHeader = request.header("Signature");
        if (isBlank(signatureInput) || isBlank(signatureHeader)) {
            throw new LumoAuthValidationException("the request carries no RFC 9421 signature");
        }
        ParsedSignatureInput parsed = parseSignatureInput(signatureInput);
        String signature = parseSignatureHeader(signatureHeader);

        // Content-Digest must match the body actually received, or an attacker
        // could replay a signature over different content.
        String digest = request.header("Content-Digest");
        if (!isBlank(digest) && !digest.equals(AAuthSigner.contentDigestSha256(request.body()))) {
            throw new LumoAuthValidationException("Content-Digest does not match the request body");
        }

        String path = request.uri().getRawPath() == null || request.uri().getRawPath().isEmpty() ? "/" : request.uri().getRawPath();
        String query = request.uri().getRawQuery() == null || request.uri().getRawQuery().isEmpty() ? "" : "?" + request.uri().getRawQuery();
        Map<String, String> values = new LinkedHashMap<>();
        values.put("@method", request.method().toUpperCase(java.util.Locale.ROOT));
        values.put("@authority", request.authority());
        values.put("@path", path);
        values.put("@query", query);
        values.put("signature-key", orEmpty(request.header("Signature-Key")));
        values.put("content-digest", orEmpty(digest));
        values.put("content-type", orEmpty(request.header("Content-Type")));
        values.put("authorization", orEmpty(request.header("Authorization")));

        PublicKey key = confirmation.toPublicKey();
        String base = AAuthSigner.buildSignatureBase(parsed.components(), values, parsed.created(), parsed.nonce());
        if (!AAuthSigner.verifySignatureBase(base, signature, key)) {
            throw new LumoAuthValidationException("proof-of-possession signature verification failed");
        }
    }

    record ParsedSignatureInput(List<String> components, long created, String nonce) {
    }

    /** Reads {@code sig1=("@method" "@authority" ...);created=1700000000;nonce="..."}. */
    static ParsedSignatureInput parseSignatureInput(String header) {
        int open = header.indexOf('(');
        int close = header.indexOf(')');
        if (open < 0 || close < open) {
            throw new LumoAuthValidationException("malformed Signature-Input: no covered component list");
        }
        List<String> components = new ArrayList<>();
        for (String field : header.substring(open + 1, close).trim().split("\\s+")) {
            if (!field.isEmpty()) {
                components.add(field.replace("\"", ""));
            }
        }
        long created = 0;
        String nonce = null;
        for (String param : header.substring(close + 1).split(";")) {
            String trimmed = param.trim();
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = trimmed.substring(0, eq);
            String value = trimmed.substring(eq + 1).replace("\"", "");
            if ("created".equals(name)) {
                if (!value.matches("\\d+")) {
                    throw new LumoAuthValidationException("malformed Signature-Input: non-numeric created");
                }
                created = Long.parseLong(value);
            } else if ("nonce".equals(name)) {
                nonce = value;
            }
        }
        if (created == 0 || isBlank(nonce)) {
            throw new LumoAuthValidationException("malformed Signature-Input: created and nonce are both required");
        }
        return new ParsedSignatureInput(components, created, nonce);
    }

    /** Reads {@code sig1=:<base64url>:}. */
    static String parseSignatureHeader(String header) {
        int eq = header.indexOf('=');
        if (eq < 0) {
            throw new LumoAuthValidationException("malformed Signature header");
        }
        String value = header.substring(eq + 1).trim();
        if (value.length() < 2 || !value.startsWith(":") || !value.endsWith(":")) {
            throw new LumoAuthValidationException("malformed Signature header: expected a :...: byte sequence");
        }
        return value.substring(1, value.length() - 1);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }
}
