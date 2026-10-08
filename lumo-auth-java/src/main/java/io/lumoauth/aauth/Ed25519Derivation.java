package io.lumoauth.aauth;

import io.lumoauth.errors.LumoAuthValidationException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Derives an Ed25519 public key from its private seed (RFC 8032 §5.1.5). The
 * JDK's EdDSA provider exposes the seed but no public-key derivation, so this
 * performs the scalar multiplication itself on the twisted Edwards curve.
 */
final class Ed25519Derivation {

    private static final java.math.BigInteger P = java.math.BigInteger.TWO.pow(255).subtract(java.math.BigInteger.valueOf(19));
    private static final java.math.BigInteger D = java.math.BigInteger.valueOf(-121665)
        .multiply(java.math.BigInteger.valueOf(121666).modInverse(P)).mod(P);
    private static final java.math.BigInteger I = java.math.BigInteger.TWO.modPow(P.subtract(java.math.BigInteger.ONE).divide(java.math.BigInteger.valueOf(4)), P);
    private static final java.math.BigInteger BY = java.math.BigInteger.valueOf(4).multiply(java.math.BigInteger.valueOf(5).modInverse(P)).mod(P);
    private static final java.math.BigInteger BX = recoverX(BY);

    private Ed25519Derivation() {
    }

    static PublicKey publicKey(PrivateKey key) throws GeneralSecurityException {
        byte[] seed = ((EdECPrivateKey) key).getBytes()
            .orElseThrow(() -> new LumoAuthValidationException("the Ed25519 private key does not expose its seed"));
        byte[] h = MessageDigest.getInstance("SHA-512").digest(seed);
        byte[] a = Arrays.copyOf(h, 32);
        a[0] &= (byte) 0xF8;
        a[31] &= (byte) 0x7F;
        a[31] |= (byte) 0x40;
        java.math.BigInteger scalar = littleEndian(a);
        java.math.BigInteger[] point = scalarMultiply(scalar, new java.math.BigInteger[] {BX, BY});
        byte[] encoded = encodePoint(point);
        byte[] spki = new byte[Jwk.ED25519_SPKI_PREFIX.length + 32];
        System.arraycopy(Jwk.ED25519_SPKI_PREFIX, 0, spki, 0, Jwk.ED25519_SPKI_PREFIX.length);
        System.arraycopy(encoded, 0, spki, Jwk.ED25519_SPKI_PREFIX.length, 32);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
    }

    private static java.math.BigInteger recoverX(java.math.BigInteger y) {
        java.math.BigInteger y2 = y.multiply(y).mod(P);
        java.math.BigInteger xx = y2.subtract(java.math.BigInteger.ONE)
            .multiply(D.multiply(y2).add(java.math.BigInteger.ONE).modInverse(P)).mod(P);
        java.math.BigInteger x = xx.modPow(P.add(java.math.BigInteger.valueOf(3)).divide(java.math.BigInteger.valueOf(8)), P);
        if (!x.multiply(x).subtract(xx).mod(P).equals(java.math.BigInteger.ZERO)) {
            x = x.multiply(I).mod(P);
        }
        if (x.testBit(0)) {
            x = P.subtract(x);
        }
        return x;
    }

    private static java.math.BigInteger[] add(java.math.BigInteger[] p, java.math.BigInteger[] q) {
        java.math.BigInteger x1 = p[0], y1 = p[1], x2 = q[0], y2 = q[1];
        java.math.BigInteger dxy = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(P);
        java.math.BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1)).multiply(java.math.BigInteger.ONE.add(dxy).modInverse(P)).mod(P);
        java.math.BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2)).multiply(java.math.BigInteger.ONE.subtract(dxy).modInverse(P)).mod(P);
        return new java.math.BigInteger[] {x3, y3};
    }

    private static java.math.BigInteger[] scalarMultiply(java.math.BigInteger e, java.math.BigInteger[] point) {
        java.math.BigInteger[] result = new java.math.BigInteger[] {java.math.BigInteger.ZERO, java.math.BigInteger.ONE};
        java.math.BigInteger[] base = point;
        for (int i = 0; i < e.bitLength(); i++) {
            if (e.testBit(i)) {
                result = add(result, base);
            }
            base = add(base, base);
        }
        return result;
    }

    private static byte[] encodePoint(java.math.BigInteger[] point) {
        byte[] y = toLittleEndian(point[1], 32);
        if (point[0].testBit(0)) {
            y[31] |= (byte) 0x80;
        }
        return y;
    }

    private static java.math.BigInteger littleEndian(byte[] bytes) {
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }
        return new java.math.BigInteger(1, reversed);
    }

    private static byte[] toLittleEndian(java.math.BigInteger value, int size) {
        byte[] big = value.toByteArray();
        byte[] out = new byte[size];
        int start = big.length > size ? big.length - size : 0;
        int count = big.length - start;
        for (int i = 0; i < count; i++) {
            out[i] = big[big.length - 1 - i];
        }
        return out;
    }
}
