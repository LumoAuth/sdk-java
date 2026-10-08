package io.lumoauth.aauth;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.support.ContractFiles;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * RFC 9421 conformance against the shared vector
 * ({@code sdk-contract/vectors/aauth-rfc9421.json}). Ed25519 is deterministic, so
 * the signature must match byte for byte. The vector is embedded so the suite is
 * meaningful in a standalone checkout; when the contract is present the embedded
 * copy is asserted equal to it.
 */
class AAuthSignerTest {

    static final String PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n";
    static final String PUBLIC_JWK_X = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    static final String URL = "https://auth.acme.test/orgs/acme-corp/api/v1/aauth/agent/token";
    static final String BODY = "{\"request_type\": \"auth\", \"resource_token\": \"RESOURCE_TOKEN_FIXED\", \"scope\": \"read write\"}";
    static final long CREATED = 1750000000L;
    static final String NONCE = "AAECAwQFBgcICQoLDA0ODw";
    static final String AGENT_TOKEN = "AGENT_TOKEN_FIXED";
    static final String CONTENT_DIGEST = "sha-256=:maoKTEBGVoe/uXlHmt4EeWj7K7xo71Ag/qIPObi3vPw=:";
    static final String SIGNATURE_INPUT = "sig1=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"content-digest\" \"content-type\" \"authorization\");created=1750000000;nonce=\"AAECAwQFBgcICQoLDA0ODw\"";
    static final String SIGNATURE = "sig1=:sr5ZGEA2-LkKN4RvFrpYxhaGPB-tf1STvf1W0bl_UAFt1Rjn_wKKCouOHsFamkDAf85UpwF_HOJXLs07-bynCw:";

    @Test
    void embeddedVectorMatchesTheContract() {
        assumeTrue(ContractFiles.dir().isPresent(), "sdk-contract not found");
        JsonNode v = ContractFiles.load("vectors/aauth-rfc9421.json");
        assertThat(v.get("private_key_pem").asText()).isEqualTo(PRIVATE_KEY_PEM);
        assertThat(v.get("public_jwk_x").asText()).isEqualTo(PUBLIC_JWK_X);
        assertThat(v.get("request").get("body").asText()).isEqualTo(BODY);
        assertThat(v.get("expected").get("signature").asText()).isEqualTo(SIGNATURE);
        assertThat(v.get("expected").get("signature_input").asText()).isEqualTo(SIGNATURE_INPUT);
        List<String> covered = new java.util.ArrayList<>();
        v.get("covered_components").forEach(c -> covered.add(c.asText()));
        assertThat(covered).isEqualTo(AAuthSigner.COVERED_COMPONENTS);
    }

    @Test
    void signReproducesThePythonSignatureByteForByte() {
        PrivateKey key = AAuthKeys.loadPrivateKey(PRIVATE_KEY_PEM);
        Map<String, String> headers = AAuthSigner.signRequest(key, "POST", URL,
            SignOptions.body(BODY.getBytes(StandardCharsets.UTF_8)).agentToken(AGENT_TOKEN).created(CREATED).nonce(NONCE));
        assertThat(headers.get("Content-Digest")).isEqualTo(CONTENT_DIGEST);
        assertThat(headers.get("Content-Type")).isEqualTo("application/json");
        assertThat(headers.get("Signature-Input")).isEqualTo(SIGNATURE_INPUT);
        assertThat(headers.get("Signature")).isEqualTo(SIGNATURE);
        assertThat(headers.get("Agent-Auth")).isEqualTo("agent_token=" + AGENT_TOKEN);
        assertThat(headers).doesNotContainKey("Signature-Key");
    }

    @Test
    void derivedPublicKeyMatchesTheVector() {
        Jwk jwk = AAuthKeys.publicJwk(PRIVATE_KEY_PEM, "key-1");
        assertThat(jwk.kty()).isEqualTo("OKP");
        assertThat(jwk.crv()).isEqualTo("Ed25519");
        assertThat(jwk.x()).isEqualTo(PUBLIC_JWK_X);
        assertThat(jwk.kid()).isEqualTo("key-1");
        // The derived key verifies what the private key signed.
        String base = "hello";
        String sig = AAuthSigner.signSignatureBase(base, AAuthKeys.loadPrivateKey(PRIVATE_KEY_PEM));
        assertThat(AAuthSigner.verifySignatureBase(base, sig, jwk.toPublicKey())).isTrue();
        assertThat(AAuthSigner.verifySignatureBase(base + "x", sig, jwk.toPublicKey())).isFalse();
    }

    @Test
    void queryIsCoveredOnlyWhenPresent() {
        PrivateKey key = AAuthKeys.loadPrivateKey(PRIVATE_KEY_PEM);
        Map<String, String> headers = AAuthSigner.signRequest(key, "get", "https://API.Example.com:8443/path?x=1&y=2",
            SignOptions.NONE.created(1).nonce("n"));
        assertThat(headers.get("Signature-Input"))
            .isEqualTo("sig1=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\" \"content-digest\" \"content-type\" \"authorization\");created=1;nonce=\"n\"");
        String base = AAuthSigner.buildSignatureBase(
            List.of("@method", "@authority", "@path", "@query"),
            Map.of("@method", "GET", "@authority", "api.example.com:8443", "@path", "/path", "@query", "?x=1&y=2"), 1, "n");
        assertThat(base).startsWith("\"@method\": GET\n\"@authority\": api.example.com:8443\n\"@path\": /path\n\"@query\": ?x=1&y=2\n");
    }

    @Test
    void generatedNoncesAreUniqueAndLongEnough() {
        String a = AAuthSigner.generateNonce();
        String b = AAuthSigner.generateNonce();
        assertThat(a).isNotEqualTo(b).hasSize(22).doesNotContain("=");
    }

    @Test
    void contentDigestOfEmptyBody() {
        assertThat(AAuthSigner.contentDigestSha256(null))
            .isEqualTo("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
    }
}
