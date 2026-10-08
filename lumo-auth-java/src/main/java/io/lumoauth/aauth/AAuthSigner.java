package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthException;
import io.lumoauth.errors.LumoAuthValidationException;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * RFC 9421 HTTP Message Signing, profiled for AAuth.
 *
 * <p>The LumoAuth agent token endpoint enforces a strict profile (AAuth 1.0 §4):
 * <ul>
 *   <li>Covered components: {@code @method @authority @path signature-key content-digest
 *       content-type authorization}, plus {@code @query} if and only if the target URI has a query string.</li>
 *   <li>Signature-Input parameters: exactly {@code created} (within ±60s of the server clock)
 *       and a fresh {@code nonce} (at least 12 bytes of entropy, base64url).</li>
 *   <li>Content-Digest per RFC 9530 using STANDARD base64 ({@code sha-256=:...:}).</li>
 *   <li>The Signature value is base64url-encoded ({@code label=:...:}).</li>
 *   <li>Algorithms are dispatched by key type: Ed25519, or RSA-PSS-SHA512 (MGF1-SHA512, 64-byte salt).
 *       No {@code alg} parameter is declared.</li>
 * </ul>
 * The output is byte-compatible with the other LumoAuth SDKs and verified
 * against the shared conformance vector.
 */
public final class AAuthSigner {

    /** The components the agent token endpoint requires, in order; {@code @query} is inserted after {@code @path} when needed. */
    public static final List<String> COVERED_COMPONENTS = List.of(
        "@method", "@authority", "@path", "signature-key", "content-digest", "content-type", "authorization");

    static final String SIGNATURE_LABEL = "sig1";

    private static final SecureRandom RANDOM = new SecureRandom();

    private AAuthSigner() {
    }

    /** An RFC 9530 Content-Digest value over exact body bytes, using standard base64. */
    public static String contentDigestSha256(byte[] body) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(body == null ? new byte[0] : body);
            return "sha-256=:" + Base64.getEncoder().encodeToString(digest) + ":";
        } catch (GeneralSecurityException e) {
            throw new LumoAuthException("SHA-256 is unavailable: " + e.getMessage(), e);
        }
    }

    /** A fresh signature nonce: base64url of 16 random bytes. */
    public static String generateNonce() {
        byte[] buf = new byte[16];
        RANDOM.nextBytes(buf);
        return Jwk.b64url(buf);
    }

    /** The {@code (...);created=...;nonce="..."} string shared by the signature base and Signature-Input. */
    public static String signatureParams(List<String> components, long created, String nonce) {
        StringBuilder out = new StringBuilder("(");
        for (int i = 0; i < components.size(); i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append('"').append(components.get(i)).append('"');
        }
        return out.append(");created=").append(created).append(";nonce=\"").append(nonce).append('"').toString();
    }

    /** The RFC 9421 signature base: one {@code "<component>": <value>} line per component, then {@code @signature-params}. */
    public static String buildSignatureBase(List<String> components, Map<String, String> values, long created, String nonce) {
        StringBuilder out = new StringBuilder();
        for (String component : components) {
            String value = values.get(component);
            out.append('"').append(component).append("\": ").append(value == null ? "" : value).append('\n');
        }
        return out.append("\"@signature-params\": ").append(signatureParams(components, created, nonce)).toString();
    }

    /** Signs a signature base and returns the base64url signature. Ed25519 keys sign directly; RSA keys use RSA-PSS-SHA512. */
    public static String signSignatureBase(String signatureBase, PrivateKey key) {
        byte[] data = signatureBase.getBytes(StandardCharsets.UTF_8);
        try {
            Signature signature;
            if (isEd25519(key.getAlgorithm())) {
                signature = Signature.getInstance("Ed25519");
            } else if ("RSA".equalsIgnoreCase(key.getAlgorithm()) || "RSASSA-PSS".equalsIgnoreCase(key.getAlgorithm())) {
                signature = Signature.getInstance("RSASSA-PSS");
                signature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
            } else {
                throw new LumoAuthValidationException("AAuth signing requires an Ed25519 or RSA private key");
            }
            signature.initSign(key);
            signature.update(data);
            return Jwk.b64url(signature.sign());
        } catch (GeneralSecurityException e) {
            throw new LumoAuthException("signing failed: " + e.getMessage(), e);
        }
    }

    /** Checks a base64url signature over a signature base against the key in a token's {@code cnf.jwk}. */
    public static boolean verifySignatureBase(String signatureBase, String signatureB64Url, PublicKey key) {
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getUrlDecoder().decode(signatureB64Url.replaceAll("=+$", ""));
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] data = signatureBase.getBytes(StandardCharsets.UTF_8);
        try {
            Signature signature;
            if (isEd25519(key.getAlgorithm())) {
                signature = Signature.getInstance("Ed25519");
            } else if (key instanceof RSAPublicKey) {
                signature = Signature.getInstance("RSASSA-PSS");
                signature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
            } else {
                return false;
            }
            signature.initVerify(key);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Builds the RFC 9421 signature headers for a request under the AAuth
     * profile: Content-Digest, Content-Type, Signature-Input, Signature, and,
     * when an agent token is supplied, Agent-Auth.
     *
     * <pre>{@code
     * Map<String, String> headers = AAuthSigner.signRequest(privateKey, "POST", url,
     *     SignOptions.body(bodyBytes).agentToken(agentToken));
     * }</pre>
     */
    public static Map<String, String> signRequest(PrivateKey key, String method, String targetUrl, SignOptions options) {
        SignOptions opts = options == null ? SignOptions.NONE : options;
        URI uri;
        try {
            uri = URI.create(targetUrl);
        } catch (IllegalArgumentException e) {
            throw new LumoAuthValidationException("could not parse the target URL \"" + targetUrl + "\": " + e.getMessage(), e);
        }
        if (uri.getHost() == null) {
            throw new LumoAuthValidationException("could not parse the target URL \"" + targetUrl + "\": no host");
        }
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery() == null || uri.getRawQuery().isEmpty() ? "" : "?" + uri.getRawQuery();
        String authority = uri.getHost().toLowerCase(Locale.ROOT) + (uri.getPort() == -1 ? "" : ":" + uri.getPort());

        String contentType = opts.contentType() == null || opts.contentType().isEmpty() ? "application/json" : opts.contentType();
        String contentDigest = contentDigestSha256(opts.body());
        long created = opts.created() != 0 ? opts.created() : System.currentTimeMillis() / 1000;
        String nonce = opts.nonce() == null || opts.nonce().isEmpty() ? generateNonce() : opts.nonce();

        // @query is covered if and only if the target URI has a query string.
        List<String> components = new ArrayList<>(List.of("@method", "@authority", "@path"));
        if (!query.isEmpty()) {
            components.add("@query");
        }
        components.addAll(List.of("signature-key", "content-digest", "content-type", "authorization"));

        Map<String, String> values = new LinkedHashMap<>();
        values.put("@method", method.toUpperCase(Locale.ROOT));
        values.put("@authority", authority);
        values.put("@path", path);
        values.put("@query", query);
        values.put("signature-key", opts.signatureKey() == null ? "" : opts.signatureKey());
        values.put("content-digest", contentDigest);
        values.put("content-type", contentType);
        values.put("authorization", opts.authorization() == null ? "" : opts.authorization());

        String signature = signSignatureBase(buildSignatureBase(components, values, created, nonce), key);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Digest", contentDigest);
        headers.put("Content-Type", contentType);
        headers.put("Signature-Input", SIGNATURE_LABEL + "=" + signatureParams(components, created, nonce));
        headers.put("Signature", SIGNATURE_LABEL + "=:" + signature + ":");
        if (opts.agentToken() != null && !opts.agentToken().isEmpty()) {
            headers.put("Agent-Auth", "agent_token=" + opts.agentToken());
        }
        if (opts.signatureKey() != null && !opts.signatureKey().isEmpty()) {
            headers.put("Signature-Key", opts.signatureKey());
        }
        return headers;
    }

    /** {@link #signRequest(PrivateKey, String, String, SignOptions)} for a PEM private key. */
    public static Map<String, String> signRequest(String privateKeyPem, String method, String targetUrl, SignOptions options) {
        return signRequest(AAuthKeys.loadPrivateKey(privateKeyPem), method, targetUrl, options);
    }

    // ── JWS verification primitives (used by AAuthVerifier) ───────────

    /** Checks a JWS signature for one of the asymmetric algorithms AAuth permits. HMAC and "none" are always rejected. */
    static boolean verifyJws(String alg, byte[] signingInput, byte[] signature, PublicKey key) {
        try {
            switch (alg) {
                case "EdDSA": {
                    if (!isEd25519(key.getAlgorithm())) {
                        return false;
                    }
                    Signature s = Signature.getInstance("Ed25519");
                    s.initVerify(key);
                    s.update(signingInput);
                    return s.verify(signature);
                }
                case "RS256", "RS384", "RS512": {
                    if (!(key instanceof RSAPublicKey)) {
                        return false;
                    }
                    Signature s = Signature.getInstance("SHA" + alg.substring(2) + "withRSA");
                    s.initVerify(key);
                    s.update(signingInput);
                    return s.verify(signature);
                }
                case "PS256", "PS384", "PS512": {
                    if (!(key instanceof RSAPublicKey)) {
                        return false;
                    }
                    String bits = alg.substring(2);
                    Signature s = Signature.getInstance("RSASSA-PSS");
                    s.setParameter(new PSSParameterSpec("SHA-" + bits, "MGF1",
                        new MGF1ParameterSpec("SHA-" + bits), Integer.parseInt(bits) / 8, 1));
                    s.initVerify(key);
                    s.update(signingInput);
                    return s.verify(signature);
                }
                case "ES256", "ES384", "ES512": {
                    if (!(key instanceof ECPublicKey)) {
                        return false;
                    }
                    // JWS uses the fixed-width IEEE P-1363 encoding, not ASN.1.
                    Signature s = Signature.getInstance("SHA" + alg.substring(2) + "withECDSAinP1363Format");
                    s.initVerify(key);
                    s.update(signingInput);
                    return s.verify(signature);
                }
                default:
                    return false;
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** Whether a JWS algorithm is usable with a key type: the check that stops an RSA key being swapped into an EdDSA slot. */
    static boolean algMatchesKeyType(String alg, String kty) {
        if (alg == null || kty == null) {
            return false;
        }
        return switch (kty) {
            case "RSA" -> alg.startsWith("RS") || alg.startsWith("PS");
            case "EC" -> alg.startsWith("ES");
            case "OKP" -> alg.equals("EdDSA");
            default -> false;
        };
    }

    static boolean isEd25519(String algorithm) {
        return "Ed25519".equalsIgnoreCase(algorithm) || "EdDSA".equalsIgnoreCase(algorithm);
    }
}
