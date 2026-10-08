package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.internal.Json;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Auth-token verification for resource servers.
 *
 * <p>{@link #verifyAuthToken} checks an {@code auth+jwt} against the issuing
 * organization's JWKS plus {@code typ}, {@code iss}, {@code aud} and {@code exp}:
 * the same checks the LumoAuth server performs, revocation excepted. Then
 * enforce proof-of-possession over the incoming request with
 * {@link AAuthClaims#verifyProofOfPossession}:
 *
 * <pre>{@code
 * AAuthClaims claims = AAuthVerifier.verifyAuthToken(bearer,
 *     VerifyOptions.of("https://app.lumoauth.dev/orgs/acme-corp/api/v1", "https://api.example.com"));
 * claims.verifyProofOfPossession(new IncomingRequest(method, uri, headers, body));
 * }</pre>
 *
 * HMAC and "none" algorithms are always rejected, and the algorithm must match
 * the key type published in the JWKS.
 */
public final class AAuthVerifier {

    private AAuthVerifier() {
    }

    public static AAuthClaims verifyAuthToken(String token, VerifyOptions options) {
        if (options == null || options.issuer() == null || options.issuer().isBlank()) {
            throw new LumoAuthConfigException("issuer is required to verify an auth token");
        }
        if (options.resource() == null || options.resource().isBlank()) {
            throw new LumoAuthConfigException("resource is required to verify an auth token");
        }
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3) {
            throw new LumoAuthValidationException("invalid JWT: expected three dot-separated segments");
        }

        Map<String, Object> header = decodeSegment(parts[0]);
        if (!"auth+jwt".equals(header.get("typ"))) {
            throw new LumoAuthValidationException("unexpected token type \"" + header.get("typ") + "\": expected auth+jwt");
        }
        String alg = header.get("alg") instanceof String s ? s : "";
        String kid = header.get("kid") instanceof String s ? s : "";
        if (alg.isEmpty() || kid.isEmpty()) {
            throw new LumoAuthValidationException("the JOSE header is missing alg or kid");
        }

        Map<String, Object> claims = decodeSegment(parts[1]);
        // Check the issuer before fetching anything from it.
        if (!options.issuer().equals(claims.get("iss"))) {
            throw new LumoAuthValidationException("untrusted issuer \"" + claims.get("iss") + "\"");
        }

        Jwks jwks = options.jwks() != null ? options.jwks() : fetchIssuerJwks(options.issuer(), options.httpClient());
        Jwk jwk = jwks.find(kid).orElseThrow(() ->
            new LumoAuthValidationException("no key with kid \"" + kid + "\" in the issuer JWKS"));
        if (!AAuthSigner.algMatchesKeyType(alg, jwk.kty())) {
            throw new LumoAuthValidationException("algorithm " + alg + " is incompatible with key type " + jwk.kty());
        }
        if (jwk.alg() != null && !jwk.alg().isEmpty() && !jwk.alg().equals(alg)) {
            throw new LumoAuthValidationException("algorithm " + alg + " does not match the key's declared alg " + jwk.alg());
        }

        PublicKey key = jwk.toPublicKey();
        byte[] signature;
        try {
            signature = Base64.getUrlDecoder().decode(parts[2].replaceAll("=+$", ""));
        } catch (IllegalArgumentException e) {
            throw new LumoAuthValidationException("could not decode the JWT signature: " + e.getMessage(), e);
        }
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!AAuthSigner.verifyJws(alg, signingInput, signature, key)) {
            throw new LumoAuthValidationException("signature verification failed");
        }

        // Temporal and audience checks come after the signature, as on the
        // server: never trust claim values from an unverified token.
        long exp = longClaim(claims, "exp");
        if (exp == 0) {
            throw new LumoAuthValidationException("the token has no exp claim");
        }
        Duration skew = options.clockSkew() == null ? Duration.ZERO : options.clockSkew();
        if (Instant.now().minus(skew).getEpochSecond() > exp) {
            throw new LumoAuthValidationException("the auth token has expired");
        }
        String audience = audience(claims.get("aud"));
        if (!options.resource().equals(audience)) {
            throw new LumoAuthValidationException("invalid audience \"" + audience + "\": this resource is \"" + options.resource() + "\"");
        }
        Jwk confirmation = confirmationKey(claims.get("cnf"));
        if (confirmation == null) {
            throw new LumoAuthValidationException("the token has no cnf.jwk claim, so it cannot be bound to a key");
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> act = claims.get("act") instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
        return new AAuthClaims(
            string(claims, "iss"), audience, exp, longClaim(claims, "iat"), string(claims, "jti"),
            string(claims, "sub"), string(claims, "agent"), string(claims, "agent_delegate"),
            string(claims, "scope"), confirmation, act, claims);
    }

    /** Retrieves an AAuth issuer's signing keys from {@code {issuer}/aauth/jwks.json}. */
    public static Jwks fetchIssuerJwks(String issuer, HttpClient httpClient) {
        HttpTransport transport = new HttpTransport(new HttpTransport.Config(
            issuer, null, null, null, null, httpClient, false, null, null));
        Jwks jwks = transport.send("GET", "/aauth/jwks.json", ApiRequest.empty().noAuth(), Jwks.class);
        if (jwks == null || jwks.keys().isEmpty()) {
            throw new LumoAuthValidationException("the issuer JWKS contains no keys");
        }
        return jwks;
    }

    // ── Internal ──────────────────────────────────────────────────────

    static Map<String, Object> decodeSegment(String segment) {
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(segment.replaceAll("=+$", ""));
        } catch (IllegalArgumentException e) {
            throw new LumoAuthValidationException("could not base64url-decode the JWT segment: " + e.getMessage(), e);
        }
        Map<String, Object> parsed = Json.toMap(Json.parse(decoded, "JWT segment"));
        if (parsed.isEmpty()) {
            throw new LumoAuthValidationException("could not decode the JWT segment as a JSON object");
        }
        return parsed;
    }

    private static String audience(Object aud) {
        if (aud instanceof String s) {
            return s;
        }
        if (aud instanceof List<?> list && list.size() == 1 && list.get(0) instanceof String s) {
            return s;
        }
        return aud == null ? "" : String.valueOf(aud);
    }

    private static Jwk confirmationKey(Object cnf) {
        if (!(cnf instanceof Map<?, ?> map) || !(map.get("jwk") instanceof Map<?, ?> jwk)) {
            return null;
        }
        Jwk key = Json.convert(Json.mapper().valueToTree(jwk), Jwk.class, "cnf.jwk");
        return key == null || key.kty() == null || key.kty().isEmpty() ? null : key;
    }

    private static long longClaim(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof Number n ? n.longValue() : 0;
    }

    private static String string(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof String s ? s : null;
    }
}
