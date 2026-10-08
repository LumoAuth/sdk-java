package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthException;
import io.lumoauth.errors.LumoAuthValidationException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Key handling for the AAuth protocol: Ed25519 key generation, PEM loading,
 * and JWK conversion. Everything uses the JDK's own providers; no third-party
 * crypto library is involved.
 */
public final class AAuthKeys {

    /** The key ID used when none is given, matching the other SDKs. */
    public static final String DEFAULT_KID = "key-1";

    private static final byte[] RSA_ALGORITHM_IDENTIFIER = Base64.getDecoder().decode("MA0GCSqGSIb3DQEBAQUA");

    private AAuthKeys() {
    }

    /**
     * Creates an Ed25519 key pair for AAuth. Register {@code jwks} with LumoAuth
     * and keep {@code privateKeyPem} secret.
     */
    public static Keypair generateKeypair(String kid) {
        String keyId = kid == null || kid.isBlank() ? DEFAULT_KID : kid;
        try {
            KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            Jwk jwk = Jwk.ed25519(rawEd25519PublicKey(pair.getPublic())).withUse("sig").withKid(keyId);
            return new Keypair(
                pem("PRIVATE KEY", pair.getPrivate().getEncoded()),
                pem("PUBLIC KEY", pair.getPublic().getEncoded()),
                jwk,
                Jwks.of(jwk));
        } catch (GeneralSecurityException e) {
            throw new LumoAuthException("could not generate an Ed25519 key: " + e.getMessage(), e);
        }
    }

    public static Keypair generateKeypair() {
        return generateKeypair(null);
    }

    /**
     * Parses a PEM private key for AAuth signing: an Ed25519 or RSA key in
     * PKCS#8 ({@code PRIVATE KEY}), or an RSA key in PKCS#1 ({@code RSA PRIVATE KEY}).
     */
    public static PrivateKey loadPrivateKey(String pem) {
        PemBlock block = decodePem(pem);
        byte[] pkcs8 = switch (block.type()) {
            case "RSA PRIVATE KEY" -> wrapPkcs1(block.bytes());
            case "PRIVATE KEY" -> block.bytes();
            case "EC PRIVATE KEY" -> throw new LumoAuthValidationException("AAuth requires an Ed25519 or RSA private key");
            default -> block.bytes();
        };
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        for (String algorithm : List.of("Ed25519", "RSA")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (InvalidKeySpecException e) {
                // try the next algorithm
            } catch (GeneralSecurityException e) {
                throw new LumoAuthValidationException("could not parse the private key: " + e.getMessage(), e);
            }
        }
        throw new LumoAuthValidationException("AAuth requires an Ed25519 or RSA private key");
    }

    /** The public JWK for a PEM private key. */
    public static Jwk publicJwk(String privateKeyPem, String kid) {
        return jwkFromPublicKey(publicKeyOf(loadPrivateKey(privateKeyPem))).withKid(kid);
    }

    /** Derives the public key of a private key. */
    public static PublicKey publicKeyOf(PrivateKey key) {
        try {
            if (key instanceof java.security.interfaces.RSAPrivateCrtKey rsa) {
                return KeyFactory.getInstance("RSA").generatePublic(
                    new java.security.spec.RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
            }
            if ("Ed25519".equalsIgnoreCase(key.getAlgorithm()) || "EdDSA".equalsIgnoreCase(key.getAlgorithm())) {
                // The JDK's EdDSA provider exposes the seed but no derivation.
                return Ed25519Derivation.publicKey(key);
            }
            throw new LumoAuthValidationException("unsupported private key type " + key.getAlgorithm());
        } catch (GeneralSecurityException e) {
            throw new LumoAuthValidationException("could not derive the public key: " + e.getMessage(), e);
        }
    }

    /** Converts a public key into its JWK representation. */
    public static Jwk jwkFromPublicKey(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return new Jwk("RSA", null, null, null, Jwk.b64url(unsigned(rsa.getModulus())),
                Jwk.b64url(unsigned(rsa.getPublicExponent())), null, null, null);
        }
        if (key instanceof ECPublicKey ec) {
            int size = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            String crv = switch (size) {
                case 32 -> "P-256";
                case 48 -> "P-384";
                case 66 -> "P-521";
                default -> throw new LumoAuthValidationException("unsupported EC curve size " + size);
            };
            return new Jwk("EC", crv, Jwk.b64url(leftPad(unsigned(ec.getW().getAffineX()), size)),
                Jwk.b64url(leftPad(unsigned(ec.getW().getAffineY()), size)), null, null, null, null, null);
        }
        if ("Ed25519".equalsIgnoreCase(key.getAlgorithm()) || "EdDSA".equalsIgnoreCase(key.getAlgorithm())) {
            return Jwk.ed25519(rawEd25519PublicKey(key));
        }
        throw new LumoAuthValidationException("unsupported public key type for JWK conversion");
    }

    /** The raw 32-byte Ed25519 public key (the tail of its SPKI encoding). */
    static byte[] rawEd25519PublicKey(PublicKey key) {
        byte[] encoded = key.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    /** PEM-encodes DER bytes with 64-character lines. */
    public static String pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    record PemBlock(String type, byte[] bytes) {
    }

    static PemBlock decodePem(String rawPem) {
        // Keys pasted into environment variables or YAML often carry literal "\n" sequences.
        String pem = rawPem == null ? null : rawPem.replace("\\n", "\n");
        if (pem == null || !pem.contains("-----BEGIN ")) {
            throw new LumoAuthValidationException("could not parse the private key: no PEM block found");
        }
        int begin = pem.indexOf("-----BEGIN ");
        int typeEnd = pem.indexOf("-----", begin + 11);
        int end = pem.indexOf("-----END ", typeEnd);
        if (typeEnd < 0 || end < 0) {
            throw new LumoAuthValidationException("could not parse the private key: malformed PEM block");
        }
        String type = pem.substring(begin + 11, typeEnd).strip();
        String body = pem.substring(typeEnd + 5, end).replaceAll("\\s+", "");
        try {
            return new PemBlock(type, Base64.getDecoder().decode(body));
        } catch (IllegalArgumentException e) {
            throw new LumoAuthValidationException("could not parse the private key: invalid base64 in PEM block", e);
        }
    }

    /** Wraps a PKCS#1 RSAPrivateKey in the PKCS#8 PrivateKeyInfo structure the JDK expects. */
    static byte[] wrapPkcs1(byte[] pkcs1) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.writeBytes(new byte[] {0x02, 0x01, 0x00}); // INTEGER 0 (version)
        inner.writeBytes(RSA_ALGORITHM_IDENTIFIER);       // SEQUENCE { rsaEncryption OID, NULL }
        inner.writeBytes(der(0x04, pkcs1));               // OCTET STRING { PKCS#1 }
        return der(0x30, inner.toByteArray());
    }

    static byte[] der(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = content.length;
        if (length < 0x80) {
            out.write(length);
        } else {
            byte[] lengthBytes = BigInteger.valueOf(length).toByteArray();
            if (lengthBytes[0] == 0) {
                lengthBytes = Arrays.copyOfRange(lengthBytes, 1, lengthBytes.length);
            }
            out.write(0x80 | lengthBytes.length);
            out.writeBytes(lengthBytes);
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    static byte[] leftPad(byte[] data, int size) {
        if (data.length >= size) {
            return data;
        }
        byte[] padded = new byte[size];
        System.arraycopy(data, 0, padded, size - data.length, data.length);
        return padded;
    }
}
