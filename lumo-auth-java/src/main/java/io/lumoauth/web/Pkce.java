package io.lumoauth.web;

import io.lumoauth.errors.LumoAuthException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/** RFC 7636 PKCE: a verifier and its S256 challenge, plus random state tokens. */
public final class Pkce {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** A generated verifier/challenge pair. */
    public record Pair(String verifier, String challenge) {
    }

    private Pkce() {
    }

    /** A fresh 48-byte verifier and its S256 challenge. */
    public static Pair generate() {
        String verifier = randomToken(48);
        return new Pair(verifier, challenge(verifier));
    }

    /** The S256 challenge for a verifier. */
    public static String challenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new LumoAuthException("SHA-256 is unavailable: " + e.getMessage(), e);
        }
    }

    /** {@code byteLength} random bytes, base64url-encoded without padding (an OAuth state, for instance). */
    public static String randomToken(int byteLength) {
        byte[] buf = new byte[byteLength];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
