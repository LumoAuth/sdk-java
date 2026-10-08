package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthValidationException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AAuthKeysTest {

    @Test
    void generatesAnEd25519KeypairThatRoundTrips() {
        Keypair pair = AAuthKeys.generateKeypair("agent-key");
        assertThat(pair.privateKeyPem()).startsWith("-----BEGIN PRIVATE KEY-----\n").endsWith("-----END PRIVATE KEY-----\n");
        assertThat(pair.publicKeyPem()).startsWith("-----BEGIN PUBLIC KEY-----\n");
        assertThat(pair.jwk().kid()).isEqualTo("agent-key");
        assertThat(pair.jwk().use()).isEqualTo("sig");
        assertThat(pair.jwks().keys()).containsExactly(pair.jwk());
        // Loading the PEM back derives the same public key.
        assertThat(AAuthKeys.publicJwk(pair.privateKeyPem(), "agent-key").x()).isEqualTo(pair.jwk().x());
        assertThat(AAuthKeys.generateKeypair().jwk().kid()).isEqualTo(AAuthKeys.DEFAULT_KID);
        assertThat(pair.jwk().thumbprint()).hasSize(43);
    }

    @Test
    void loadsRsaInPkcs8AndPkcs1AndSignsWithPss() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair rsa = generator.generateKeyPair();
        String pkcs8 = AAuthKeys.pem("PRIVATE KEY", rsa.getPrivate().getEncoded());
        PrivateKey loaded = AAuthKeys.loadPrivateKey(pkcs8);
        assertThat(loaded).isInstanceOf(RSAPrivateCrtKey.class);

        // PKCS#1 is the PKCS#8 PrivateKeyInfo's inner OCTET STRING; unwrap it to build the fixture.
        byte[] der = rsa.getPrivate().getEncoded();
        byte[] pkcs1 = unwrapPkcs8(der);
        PrivateKey fromPkcs1 = AAuthKeys.loadPrivateKey(AAuthKeys.pem("RSA PRIVATE KEY", pkcs1));
        assertThat(fromPkcs1.getEncoded()).isEqualTo(loaded.getEncoded());

        Jwk jwk = AAuthKeys.jwkFromPublicKey(rsa.getPublic());
        assertThat(jwk.kty()).isEqualTo("RSA");
        assertThat(jwk.e()).isEqualTo("AQAB");
        String sig = AAuthSigner.signSignatureBase("base", loaded);
        assertThat(AAuthSigner.verifySignatureBase("base", sig, jwk.toPublicKey())).isTrue();
        assertThat(AAuthSigner.verifySignatureBase("other", sig, jwk.toPublicKey())).isFalse();
        assertThat(jwk.thumbprint()).hasSize(43);
    }

    @Test
    void rejectsMalformedAndUnsupportedKeys() {
        assertThatThrownBy(() -> AAuthKeys.loadPrivateKey("not a pem")).isInstanceOf(LumoAuthValidationException.class)
            .hasMessageContaining("no PEM block");
        assertThatThrownBy(() -> AAuthKeys.loadPrivateKey("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"))
            .isInstanceOf(LumoAuthValidationException.class).hasMessageContaining("Ed25519 or RSA");
        assertThatThrownBy(() -> AAuthKeys.loadPrivateKey("-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}) + "\n-----END PRIVATE KEY-----\n"))
            .isInstanceOf(LumoAuthValidationException.class);
    }

    @Test
    void ecJwksConvertToKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair ec = generator.generateKeyPair();
        Jwk jwk = AAuthKeys.jwkFromPublicKey(ec.getPublic());
        assertThat(jwk.kty()).isEqualTo("EC");
        assertThat(jwk.crv()).isEqualTo("P-256");
        assertThat(jwk.toPublicKey().getEncoded()).isEqualTo(ec.getPublic().getEncoded());
    }

    /** Strips the PKCS#8 wrapper (version + algorithm identifier) to recover the inner PKCS#1 bytes. */
    private static byte[] unwrapPkcs8(byte[] pkcs8) {
        // SEQUENCE { INTEGER 0, SEQUENCE { OID, NULL }, OCTET STRING { pkcs1 } }
        int i = 0;
        i = skipHeader(pkcs8, i);           // outer SEQUENCE
        i += 3;                             // INTEGER 0 (02 01 00)
        i = skipHeader(pkcs8, i);           // algorithm SEQUENCE header
        i += 11 + 2;                        // OID rsaEncryption (06 09 + 9 bytes) + NULL (05 00)
        int start = skipHeader(pkcs8, i);   // OCTET STRING header
        return java.util.Arrays.copyOfRange(pkcs8, start, pkcs8.length);
    }

    private static int skipHeader(byte[] der, int i) {
        int length = der[i + 1] & 0xFF;
        if (length < 0x80) {
            return i + 2;
        }
        return i + 2 + (length & 0x7F);
    }
}
