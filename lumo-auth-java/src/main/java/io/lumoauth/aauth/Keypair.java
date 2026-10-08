package io.lumoauth.aauth;

/**
 * A freshly generated AAuth signing key.
 *
 * @param privateKeyPem the PKCS#8 private key; store it in a secret manager
 * @param publicKeyPem  the SPKI public key
 * @param jwk           the public key with use "sig" and the requested kid
 * @param jwks          a key set ready to publish at {@code /.well-known/jwks.json}
 */
public record Keypair(String privateKeyPem, String publicKeyPem, Jwk jwk, Jwks jwks) {
}
