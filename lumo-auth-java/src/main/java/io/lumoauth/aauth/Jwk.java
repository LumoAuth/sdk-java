package io.lumoauth.aauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.Json;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A JSON Web Key. Only the members AAuth uses are modelled.
 *
 * @param kty "OKP", "RSA" or "EC"
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Jwk(
    @JsonProperty("kty") String kty,
    @JsonProperty("crv") String crv,
    @JsonProperty("x") String x,
    @JsonProperty("y") String y,
    @JsonProperty("n") String n,
    @JsonProperty("e") String e,
    @JsonProperty("use") String use,
    @JsonProperty("kid") String kid,
    @JsonProperty("alg") String alg
) {
    /** The SPKI DER prefix for an Ed25519 public key; the raw 32 key bytes follow it. */
    static final byte[] ED25519_SPKI_PREFIX = Base64.getDecoder().decode("MCowBQYDK2VwAyEA");

    public static Jwk ed25519(byte[] rawPublicKey) {
        return new Jwk("OKP", "Ed25519", b64url(rawPublicKey), null, null, null, null, null, null);
    }

    public Jwk withKid(String newKid) {
        return new Jwk(kty, crv, x, y, n, e, use, newKid, alg);
    }

    public Jwk withUse(String newUse) {
        return new Jwk(kty, crv, x, y, n, e, newUse, kid, alg);
    }

    /** This key as a map, in the member order it was declared. */
    public Map<String, Object> toMap() {
        return Json.toMap(Json.mapper().valueToTree(this));
    }

    /** Converts the JWK into a JCA public key for signature verification. */
    public PublicKey toPublicKey() {
        try {
            switch (kty == null ? "" : kty) {
                case "OKP": {
                    if (!"Ed25519".equals(crv)) {
                        throw new LumoAuthValidationException("unsupported OKP curve \"" + crv + "\"");
                    }
                    byte[] raw = b64urlDecode(x, "x");
                    if (raw.length != 32) {
                        throw new LumoAuthValidationException("Ed25519 public key must be 32 bytes (got " + raw.length + ")");
                    }
                    byte[] spki = new byte[ED25519_SPKI_PREFIX.length + raw.length];
                    System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
                    System.arraycopy(raw, 0, spki, ED25519_SPKI_PREFIX.length, raw.length);
                    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
                }
                case "RSA": {
                    BigInteger modulus = new BigInteger(1, b64urlDecode(n, "n"));
                    BigInteger exponent = new BigInteger(1, b64urlDecode(e, "e"));
                    return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
                }
                case "EC": {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                    params.init(new ECGenParameterSpec(curveName(crv)));
                    ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
                    ECPoint point = new ECPoint(new BigInteger(1, b64urlDecode(x, "x")), new BigInteger(1, b64urlDecode(y, "y")));
                    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
                }
                default:
                    throw new LumoAuthValidationException("unsupported JWK key type \"" + kty + "\"");
            }
        } catch (GeneralSecurityException ex) {
            throw new LumoAuthValidationException("could not build a public key from the JWK: " + ex.getMessage(), ex);
        }
    }

    /**
     * The RFC 7638 thumbprint: the base64url SHA-256 of the key's canonical
     * form. AAuth uses it as the {@code jkt} value binding a token to a key.
     */
    public String thumbprint() {
        Map<String, String> canonical = new LinkedHashMap<>();
        switch (kty == null ? "" : kty) {
            case "OKP" -> {
                canonical.put("crv", crv);
                canonical.put("kty", kty);
                canonical.put("x", x);
            }
            case "EC" -> {
                canonical.put("crv", crv);
                canonical.put("kty", kty);
                canonical.put("x", x);
                canonical.put("y", y);
            }
            case "RSA" -> {
                canonical.put("e", e);
                canonical.put("kty", kty);
                canonical.put("n", n);
            }
            default -> throw new LumoAuthValidationException("unsupported key type for a thumbprint: \"" + kty + "\"");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(Json.encode(canonical));
            return b64url(digest);
        } catch (GeneralSecurityException ex) {
            throw new LumoAuthValidationException("SHA-256 is unavailable: " + ex.getMessage(), ex);
        }
    }

    static String curveName(String crv) {
        return switch (crv == null ? "" : crv) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> throw new LumoAuthValidationException("unsupported EC curve \"" + crv + "\"");
        };
    }

    static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    static byte[] b64urlDecode(String value, String member) {
        if (value == null) {
            throw new LumoAuthValidationException("the JWK has no \"" + member + "\" member");
        }
        try {
            return Base64.getUrlDecoder().decode(value.replaceAll("=+$", ""));
        } catch (IllegalArgumentException ex) {
            throw new LumoAuthValidationException("could not decode the JWK " + member + " parameter: " + ex.getMessage(), ex);
        }
    }
}
