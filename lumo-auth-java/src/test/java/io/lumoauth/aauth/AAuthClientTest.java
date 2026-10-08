package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthAuthenticationException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.support.FakeServer;
import io.lumoauth.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AAuthClientTest {

    private final FakeServer server = new FakeServer();
    private final Keypair key = AAuthKeys.generateKeypair("k1");
    private final AAuthClient client = AAuthClient.builder()
        .agentIdentifier("https://agent.example.com")
        .privateKeyPem(key.privateKeyPem())
        .baseUrl(server.url())
        .orgId("acme")
        .kid("k1")
        .build();

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void configuration() {
        assertThat(client.issuer()).isEqualTo(server.url() + "/orgs/acme/api/v1");
        assertThat(client.publicJwk()).isEqualTo(key.jwk());
        assertThat(client.publicJwkThumbprint()).isEqualTo(key.jwk().thumbprint());
        assertThatThrownBy(() -> AAuthClient.builder().privateKeyPem(key.privateKeyPem()).build())
            .isInstanceOf(LumoAuthConfigException.class).hasMessageContaining("agentIdentifier");
        assertThatThrownBy(() -> AAuthClient.builder().agentIdentifier("https://a").build())
            .isInstanceOf(LumoAuthConfigException.class).hasMessageContaining("privateKeyPem");
    }

    @Test
    void requestAuthTokenSignsTheExactBytesSent() {
        server.on("/orgs/acme/api/v1/aauth/agent/token", Reply.json(Map.of(
            "request_type", "auth", "auth_token", "AUTH", "expires_in", 900, "token_type", "auth+jwt", "refresh_token", "R")));
        AAuthTokenResponse response = client.requestAuthToken("RES", "read write", "AGENT");
        assertThat(response.authToken()).isEqualTo("AUTH");
        assertThat(response.authorizationRequired()).isFalse();
        assertThat(response.refreshTokenOpt()).contains("R");

        FakeServer.Recorded req = server.only();
        assertThat(req.json()).containsEntry("request_type", "auth").containsEntry("resource_token", "RES").containsEntry("scope", "read write");
        assertThat(req.header("Agent-Auth")).isEqualTo("agent_token=AGENT");
        assertThat(req.header("Authorization")).isNull();
        assertThat(req.header("Content-Digest")).isEqualTo(AAuthSigner.contentDigestSha256(req.body().getBytes(StandardCharsets.UTF_8)));
        assertThat(req.header("Signature-Input")).startsWith("sig1=(\"@method\" \"@authority\" \"@path\" \"signature-key\"");
        // The signature verifies against the agent's public key over what the server saw.
        AAuthClaims.ParsedSignatureInput parsed = AAuthClaims.parseSignatureInput(req.header("Signature-Input"));
        Map<String, String> values = Map.of(
            "@method", "POST", "@authority", server.url().replace("http://", ""), "@path", req.path(),
            "signature-key", "", "content-digest", req.header("Content-Digest"), "content-type", "application/json", "authorization", "");
        String base = AAuthSigner.buildSignatureBase(parsed.components(), values, parsed.created(), parsed.nonce());
        assertThat(AAuthSigner.verifySignatureBase(base, AAuthClaims.parseSignatureHeader(req.header("Signature")), key.jwk().toPublicKey())).isTrue();
    }

    @Test
    void consentIsSignalledNotThrown() {
        server.on("/orgs/acme/api/v1/aauth/agent/token",
            Reply.json(401, Map.of("error", "authorization_required", "request_token", "RT", "authorization_uri", "https://consent", "expires_in", 600)));
        AAuthTokenResponse consent = client.requestAuthToken("RES", null, "AGENT");
        assertThat(consent.authorizationRequired()).isTrue();
        assertThat(consent.requestToken()).isEqualTo("RT");
        assertThat(consent.authorizationUri()).isEqualTo("https://consent");
        assertThat(consent.expiresIn()).isEqualTo(600);

        server.on("/orgs/acme/api/v1/aauth/agent/token", Reply.json(200, Map.of("request_token", "RT2", "auth_url", "https://c2")));
        AAuthTokenResponse pending = client.requestAuthToken("RES", null, "AGENT");
        assertThat(pending.authorizationRequired()).isTrue();
        assertThat(pending.authorizationUri()).isEqualTo("https://c2");

        server.on("/orgs/acme/api/v1/aauth/agent/token", Reply.json(401, Map.of("error", "invalid_agent")));
        assertThatThrownBy(() -> client.requestAuthToken("RES", null, "AGENT")).isInstanceOf(LumoAuthAuthenticationException.class);
        assertThat(client.consentUrl("R T")).isEqualTo(server.url() + "/orgs/acme/api/v1/aauth/agent/auth?request_token=R+T");
    }

    @Test
    void otherFlowsValidateAndPost() {
        server.on("/orgs/acme/api/v1/aauth/agent/token", Reply.json(Map.of("auth_token", "A")));
        assertThat(client.exchangeCode("code", "https://cb", "AGENT").authToken()).isEqualTo("A");
        assertThat(server.last().json()).containsEntry("request_type", "code").containsEntry("redirect_uri", "https://cb");
        assertThat(client.exchangeToken("UP", "RES", "AGENT").requestType()).isEqualTo("auth");
        assertThat(server.last().json()).containsEntry("request_type", "exchange");
        assertThat(client.refresh("R", "RES", "read", "AGENT").tokenType()).isEqualTo("auth+jwt");
        assertThat(server.last().json()).containsEntry("request_type", "refresh").containsEntry("scope", "read");

        assertThatThrownBy(() -> client.requestAuthToken("RES", null, "")).isInstanceOf(LumoAuthValidationException.class).hasMessageContaining("Agent-Auth");
        assertThatThrownBy(() -> client.exchangeCode("code", "", "AGENT")).hasMessageContaining("redirect URI");
        assertThatThrownBy(() -> client.refresh("R", "", null, "AGENT")).hasMessageContaining("fresh resource token");

        server.on("/orgs/acme/api/v1/aauth/token/revoke", Reply.empty(204));
        client.revoke("jti", null, "AGENT");
        assertThat(server.last().json()).containsEntry("token_type", "auth_token");

        server.on("/orgs/acme/api/v1/aauth/agent/token", Reply.json(Map.of("token_type", "auth+jwt")));
        assertThatThrownBy(() -> client.exchangeCode("code", "https://cb", "AGENT")).hasMessageContaining("no auth_token");
    }

    @Test
    void signedRequestCarriesBearerAndSignature() {
        server.on("/v1/items", Reply.json(201, Map.of("ok", true)));
        HttpResponse<byte[]> response = client.signedRequest("POST", server.url() + "/v1/items", "AUTH", Map.of("a", 1));
        assertThat(response.statusCode()).isEqualTo(201);
        FakeServer.Recorded req = server.only();
        assertThat(req.header("Authorization")).isEqualTo("Bearer AUTH");
        assertThat(req.header("Signature")).startsWith("sig1=:");
        assertThat(req.header("Agent-Auth")).isNull();
        assertThat(req.json()).containsEntry("a", 1);
    }

    @Test
    void discovery() {
        server.on("/orgs/acme/api/v1/.well-known/aauth-issuer", Reply.json(Map.of("issuer", "I", "jwks_uri", "J", "request_types_supported", List.of("auth"))));
        server.on("/orgs/acme/api/v1/.well-known/aauth-agent", Reply.json(Map.of("agent", "https://a", "name", "A")));
        server.on("/orgs/acme/api/v1/aauth/jwks.json", Reply.json(key.jwks()));
        server.on("/.well-known/aauth-resource", Reply.json(List.of(Map.of("resource", "https://r"), Map.of("resource", "https://r2"))));
        assertThat(client.discoverIssuer().requestTypesSupported()).containsExactly("auth");
        assertThat(client.discoverAgents()).extracting(AAuthAgentMetadata::agent).containsExactly("https://a");
        assertThat(client.jwks().find("k1")).isPresent();
        assertThat(client.discoverResource(server.url() + "/")).extracting(AAuthResourceMetadata::resource).containsExactly("https://r", "https://r2");
    }
}
