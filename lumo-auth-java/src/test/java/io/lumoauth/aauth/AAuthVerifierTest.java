package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.Json;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AAuthVerifierTest {

    private static final String RESOURCE = "https://api.example.com";

    private final FakeServer server = new FakeServer();
    private final Keypair issuerKey = AAuthKeys.generateKeypair("issuer-1");
    private final Keypair agentKey = AAuthKeys.generateKeypair("agent-1");
    private final String issuer = server.url() + "/orgs/acme/api/v1";

    @AfterEach
    void stop() {
        server.close();
    }

    private String token(Map<String, Object> overrides, Map<String, Object> headerOverrides, PrivateKey signer) {
        Map<String, Object> header = new LinkedHashMap<>(Map.of("alg", "EdDSA", "typ", "auth+jwt", "kid", "issuer-1"));
        header.putAll(headerOverrides);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("aud", RESOURCE);
        claims.put("exp", Instant.now().getEpochSecond() + 300);
        claims.put("iat", Instant.now().getEpochSecond());
        claims.put("jti", "jti-1");
        claims.put("agent", "https://agent.example.com");
        claims.put("scope", "read write");
        claims.put("cnf", Map.of("jwk", agentKey.jwk().toMap()));
        claims.put("act", Map.of("sub", "https://parent.example.com"));
        claims.putAll(overrides);
        String h = b64(Json.encode(header));
        String c = b64(Json.encode(claims));
        String sig = AAuthSigner.signSignatureBase(h + "." + c, signer);
        return h + "." + c + "." + sig;
    }

    private String token() {
        return token(Map.of(), Map.of(), AAuthKeys.loadPrivateKey(issuerKey.privateKeyPem()));
    }

    private static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    @Test
    void verifiesAValidTokenAgainstTheFetchedJwks() {
        server.on("/orgs/acme/api/v1/aauth/jwks.json", Reply.json(issuerKey.jwks()));
        AAuthClaims claims = AAuthVerifier.verifyAuthToken(token(), VerifyOptions.of(issuer, RESOURCE));
        assertThat(claims.issuer()).isEqualTo(issuer);
        assertThat(claims.audience()).isEqualTo(RESOURCE);
        assertThat(claims.agent()).isEqualTo("https://agent.example.com");
        assertThat(claims.scopes()).containsExactly("read", "write");
        assertThat(claims.hasScope("write")).isTrue();
        assertThat(claims.confirmation().x()).isEqualTo(agentKey.jwk().x());
        assertThat(claims.act()).containsEntry("sub", "https://parent.example.com");
        assertThat(claims.claim("jti")).contains("jti-1");
        assertThat(server.only().header("Authorization")).isNull();
    }

    @Test
    void rejectsBadTokens() {
        VerifyOptions opts = VerifyOptions.of(issuer, RESOURCE).jwks(issuerKey.jwks());
        PrivateKey signer = AAuthKeys.loadPrivateKey(issuerKey.privateKeyPem());
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken("a.b", opts)).hasMessageContaining("three dot-separated");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of(), Map.of("typ", "JWT"), signer), opts))
            .hasMessageContaining("expected auth+jwt");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of("iss", "https://evil"), Map.of(), signer), opts))
            .hasMessageContaining("untrusted issuer");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of(), Map.of("kid", "other"), signer), opts))
            .hasMessageContaining("no key with kid");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of(), Map.of("alg", "HS256"), signer), opts))
            .hasMessageContaining("incompatible with key type");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of(), Map.of("alg", "none"), signer), opts))
            .isInstanceOf(LumoAuthValidationException.class);
        // Signed by the wrong key.
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of(), Map.of(), AAuthKeys.loadPrivateKey(agentKey.privateKeyPem())), opts))
            .hasMessageContaining("signature verification failed");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of("exp", Instant.now().getEpochSecond() - 10), Map.of(), signer), opts))
            .hasMessageContaining("expired");
        assertThat(AAuthVerifier.verifyAuthToken(token(Map.of("exp", Instant.now().getEpochSecond() - 10), Map.of(), signer),
            opts.clockSkew(Duration.ofSeconds(60))).jti()).isEqualTo("jti-1");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(Map.of("aud", "https://other"), Map.of(), signer), opts))
            .hasMessageContaining("invalid audience");
        Map<String, Object> noCnf = new HashMap<>();
        noCnf.put("cnf", Map.of());
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(noCnf, Map.of(), signer), opts))
            .hasMessageContaining("cnf.jwk");
        assertThatThrownBy(() -> AAuthVerifier.verifyAuthToken(token(), VerifyOptions.of("", RESOURCE)))
            .isInstanceOf(LumoAuthConfigException.class);
    }

    @Test
    void proofOfPossessionVerifiesTheSignedRequest() {
        VerifyOptions opts = VerifyOptions.of(issuer, RESOURCE).jwks(issuerKey.jwks());
        String authToken = token();
        AAuthClaims claims = AAuthVerifier.verifyAuthToken(authToken, opts);

        byte[] body = "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8);
        String url = "https://api.example.com/v1/items?limit=5";
        Map<String, String> signed = AAuthSigner.signRequest(AAuthKeys.loadPrivateKey(agentKey.privateKeyPem()), "POST", url,
            SignOptions.body(body).authorization("Bearer " + authToken));
        Map<String, String> headers = new HashMap<>(signed);
        headers.put("Authorization", "Bearer " + authToken);
        headers.put("Host", "api.example.com");
        IncomingRequest request = new IncomingRequest("POST", URI.create(url), headers, body);
        claims.verifyProofOfPossession(request);

        // Tampered body: digest mismatch.
        IncomingRequest tampered = new IncomingRequest("POST", URI.create(url), headers, "{}".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> claims.verifyProofOfPossession(tampered)).hasMessageContaining("Content-Digest");
        // Different path: signature mismatch.
        IncomingRequest moved = new IncomingRequest("POST", URI.create("https://api.example.com/v1/other?limit=5"), headers, body);
        assertThatThrownBy(() -> claims.verifyProofOfPossession(moved)).hasMessageContaining("proof-of-possession");
        // No signature at all.
        IncomingRequest unsigned = new IncomingRequest("POST", URI.create(url), Map.of("Authorization", "Bearer x"), body);
        assertThatThrownBy(() -> claims.verifyProofOfPossession(unsigned)).hasMessageContaining("no RFC 9421 signature");
        // Signed by a key other than cnf.jwk.
        Map<String, String> wrongKey = new HashMap<>(AAuthSigner.signRequest(AAuthKeys.loadPrivateKey(issuerKey.privateKeyPem()), "POST", url,
            SignOptions.body(body).authorization("Bearer " + authToken)));
        wrongKey.put("Authorization", "Bearer " + authToken);
        assertThatThrownBy(() -> claims.verifyProofOfPossession(new IncomingRequest("POST", URI.create(url), wrongKey, body)))
            .hasMessageContaining("proof-of-possession");
    }

    @Test
    void jwksCacheFetchesOnceUntilInvalidated() {
        server.on("/orgs/acme/api/v1/aauth/jwks.json", Reply.json(issuerKey.jwks()));
        JwksCache cache = new JwksCache(issuer, Duration.ofMinutes(5), null);
        assertThat(cache.get().find("issuer-1")).isPresent();
        cache.get();
        assertThat(server.requests()).hasSize(1);
        cache.invalidate();
        cache.get();
        assertThat(server.requests()).hasSize(2);
        assertThat(AAuthVerifier.verifyAuthToken(token(), cache.verifyOptions(RESOURCE)).jti()).isEqualTo("jti-1");

        server.on("/orgs/empty/api/v1/aauth/jwks.json", Reply.json(Map.of("keys", List.of())));
        assertThatThrownBy(() -> AAuthVerifier.fetchIssuerJwks(server.url() + "/orgs/empty/api/v1", null))
            .hasMessageContaining("no keys");
    }

    @Test
    void parsesSignatureHeaders() {
        AAuthClaims.ParsedSignatureInput parsed = AAuthClaims.parseSignatureInput(
            "sig1=(\"@method\" \"@path\");created=1700000000;nonce=\"abc\"");
        assertThat(parsed.components()).containsExactly("@method", "@path");
        assertThat(parsed.created()).isEqualTo(1700000000L);
        assertThat(parsed.nonce()).isEqualTo("abc");
        assertThat(AAuthClaims.parseSignatureHeader("sig1=:YWJj:")).isEqualTo("YWJj");
        assertThatThrownBy(() -> AAuthClaims.parseSignatureInput("sig1=();created=x;nonce=\"n\"")).hasMessageContaining("non-numeric");
        assertThatThrownBy(() -> AAuthClaims.parseSignatureInput("sig1=(\"@method\")")).hasMessageContaining("created and nonce");
        assertThatThrownBy(() -> AAuthClaims.parseSignatureHeader("sig1=YWJj")).hasMessageContaining(":...:");
    }
}
