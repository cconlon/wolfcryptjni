/* WolfCryptEdDSACurve.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jce;

import java.security.MessageDigest;
import java.util.Arrays;

import com.wolfssl.wolfcrypt.Asn;
import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.Ed448;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE EdDSA curves (RFC 8032).
 *
 * Package-private, the public API exposes curve identity through standard
 * JCA names "Ed25519" / "Ed448" and NamedParameterSpec. Sizes come from
 * the native constants mirrored by the JNI classes, and every encoding or
 * validation is done by native wolfCrypt through the helpers below.
 */
enum WolfCryptEdDSACurve {

    /** Ed25519: 32-byte keys, 64-byte signatures, OID 1.3.101.112 */
    ED25519("Ed25519", Ed25519.ED25519_KEY_SIZE, Ed25519.ED25519_PUB_KEY_SIZE,
        Ed25519.ED25519_SIG_SIZE, 255, 255, "1.3.101.112"),

    /** Ed448: 57-byte keys, 114-byte signatures, OID 1.3.101.113 */
    ED448("Ed448", Ed448.ED448_KEY_SIZE, Ed448.ED448_PUB_KEY_SIZE,
        Ed448.ED448_SIG_SIZE, 448, 448, "1.3.101.113");

    static final String ALGORITHM_NAME = "EdDSA";

    private final String jcaName;
    private final int privateKeySize;
    private final int publicKeySize;
    private final int signatureSize;
    private final int keySizeBits;
    private final int yBits;
    private final String oid;

    WolfCryptEdDSACurve(String jcaName, int privateKeySize, int publicKeySize,
        int signatureSize, int keySizeBits, int yBits, String oid) {

        this.jcaName = jcaName;
        this.privateKeySize = privateKeySize;
        this.publicKeySize = publicKeySize;
        this.signatureSize = signatureSize;
        this.keySizeBits = keySizeBits;
        this.yBits = yBits;
        this.oid = oid;
    }

    /**
     * Get the JCA curve name.
     *
     * @return JCA curve name, "Ed25519" or "Ed448"
     */
    String getJcaName() {
        return jcaName;
    }

    /**
     * Get the raw private key size.
     *
     * @return raw private key size in bytes
     */
    int getPrivateKeySize() {
        return privateKeySize;
    }

    /**
     * Get the raw (compressed) public key size.
     *
     * @return raw public key size in bytes
     */
    int getPublicKeySize() {
        return publicKeySize;
    }

    /**
     * Get the signature size.
     *
     * @return signature size in bytes
     */
    int getSignatureSize() {
        return signatureSize;
    }

    /**
     * Get the key size in bits.
     *
     * @return key size in bits, 255 for Ed25519 or 448 for Ed448
     */
    int getKeySizeBits() {
        return keySizeBits;
    }

    /**
     * Get the maximum bit length of a y coordinate on this curve.
     *
     * @return maximum y coordinate bit length
     */
    int getYBits() {
        return yBits;
    }

    /**
     * Get the curve OID.
     *
     * @return dotted OID string, "1.3.101.112" or "1.3.101.113"
     */
    String getOid() {
        return oid;
    }

    /**
     * Check whether native wolfSSL was built with this curve.
     *
     * @return true if the curve is compiled into native wolfSSL, otherwise
     *         false
     */
    boolean isEnabled() {

        if (this == ED25519) {
            return FeatureDetect.Ed25519Enabled();
        }

        return FeatureDetect.Ed448Enabled();
    }

    /**
     * Look a curve up by JCA name (case-insensitive). Also accepts dotted OID
     * with or without an OID prefix.
     *
     * @param name curve name
     *
     * @return matching curve, or null if not recognized
     */
    static WolfCryptEdDSACurve fromName(String name) {

        if (name == null) {
            return null;
        }

        String n = name.trim();
        if (n.regionMatches(true, 0, "OID.", 0, 4)) {
            n = n.substring(4);
        }

        for (WolfCryptEdDSACurve c : values()) {
            if (c.jcaName.equalsIgnoreCase(n) || c.oid.equals(n)) {
                return c;
            }
        }

        return null;
    }

    /**
     * Look a curve up by the integer key size.
     *
     * @param keySize key size in bits
     *
     * @return matching curve, or null if not recognized
     */
    static WolfCryptEdDSACurve fromKeySize(int keySize) {

        switch (keySize) {
            case 255:
            case 256:
                return ED25519;
            case 448:
                return ED448;
            default:
                return null;
        }
    }

    /**
     * Identify the curve of a PKCS#8 PrivateKeyInfo / OneAsymmetricKey.
     *
     * @param der PKCS#8 DER
     *
     * @return curve, or null if native does not report an EdDSA algorithm
     *         (not an EdDSA key, not PKCS#8, or PKCS#8 support not
     *         compiled into native wolfSSL)
     */
    static WolfCryptEdDSACurve fromPkcs8Der(byte[] der) {

        if (der == null || der.length == 0) {
            return null;
        }

        try {
            int algoId = Asn.getPkcs8AlgoID(der);
            if (algoId == Asn.ED25519k) {
                return ED25519;
            }
            if (algoId == Asn.ED448k) {
                return ED448;
            }
        }
        catch (WolfCryptException e) {
            /* not something native can identify */
        }

        return null;
    }

    /**
     * Validate a raw public key (point on curve) and produce its X.509
     * SubjectPublicKeyInfo.
     *
     * @param rawPub raw public key
     *
     * @return {@code [0]} raw public key (copy), {@code [1]} SPKI DER
     *
     * @throws IllegalArgumentException if the key is the wrong length or
     *         not a valid point, or the curve is not compiled in
     */
    byte[][] importPublic(byte[] rawPub) throws IllegalArgumentException {

        if (rawPub == null || rawPub.length != publicKeySize) {
            throw new IllegalArgumentException(jcaName +
                " public key must be " + publicKeySize + " bytes");
        }

        if (this == ED25519) {
            Ed25519 k = null;
            try {
                k = new Ed25519();
                k.importPublicEx(rawPub, false);
                return new byte[][] {
                    k.exportPublic(), k.exportPublicKeyDer(true)
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed25519 public key: " + e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
        else {
            Ed448 k = null;
            try {
                k = new Ed448();
                k.importPublicEx(rawPub, false);
                return new byte[][] {
                    k.exportPublic(), k.exportPublicKeyDer(true)
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed448 public key: " + e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
    }

    /**
     * Import a raw private key, derive its public key and produce the
     * PKCS#8 v1 encoding.
     *
     * @param rawPriv raw private key
     *
     * @return {@code [0]} raw private key (copy), {@code [1]} raw public
     *         key, {@code [2]} PKCS#8 DER
     *
     * @throws IllegalArgumentException if the private key is the wrong
     *         length or the curve is not compiled in
     */
    byte[][] importPrivate(byte[] rawPriv) throws IllegalArgumentException {

        if (rawPriv == null || rawPriv.length != privateKeySize) {
            throw new IllegalArgumentException(jcaName +
                " private key must be " + privateKeySize + " bytes");
        }

        if (this == ED25519) {
            Ed25519 k = null;
            try {
                k = new Ed25519();
                k.importPrivateOnly(rawPriv);
                k.ensurePublicKey();
                return new byte[][] {
                    k.exportPrivateOnly(), k.exportPublic(),
                    k.exportPrivateKeyDer()
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed25519 private key: " + e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
        else {
            Ed448 k = null;
            try {
                k = new Ed448();
                k.importPrivateOnly(rawPriv);
                k.ensurePublicKey();
                return new byte[][] {
                    k.exportPrivateOnly(), k.exportPublic(),
                    k.exportPrivateKeyDer()
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed448 private key: " + e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
    }

    /**
     * Decode an X.509 SubjectPublicKeyInfo, return the raw public key plus
     * the canonical re-encoding.
     *
     * @param der SubjectPublicKeyInfo DER
     *
     * @return {@code [0]} raw public key, {@code [1]} canonical SPKI DER
     *
     * @throws IllegalArgumentException if the DER is not a valid key for
     *         this curve or the curve is not compiled in
     */
    byte[][] decodeSpki(byte[] der) throws IllegalArgumentException {

        if (this == ED25519) {
            Ed25519 k = null;
            try {
                k = new Ed25519();
                k.importPublicKeyDer(der);
                return new byte[][] {
                    k.exportPublic(), k.exportPublicKeyDer(true)
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed25519 SubjectPublicKeyInfo: " +
                    e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
        else {
            Ed448 k = null;
            try {
                k = new Ed448();
                k.importPublicKeyDer(der);
                return new byte[][] {
                    k.exportPublic(), k.exportPublicKeyDer(true)
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed448 SubjectPublicKeyInfo: " +
                    e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
    }

    /**
     * Decode a PKCS#8 PrivateKeyInfo / OneAsymmetricKey (v1 or v2 with
     * public key), return the raw private and public keys plus the canonical
     * PKCS#8 v1 re-encoding. The public key is derived when the DER lacks one.
     *
     * @param der PKCS#8 DER
     *
     * @return {@code [0]} raw private key, {@code [1]} raw public key,
     *         {@code [2]} canonical PKCS#8 v1 DER
     *
     * @throws IllegalArgumentException if the DER is not a valid key for
     *         this curve or the curve is not compiled in
     */
    byte[][] decodePkcs8(byte[] der) throws IllegalArgumentException {

        byte[][] v2 = null;
        byte[][] r = null;

        try {
            return decodePkcs8Native(der);
        }
        catch (IllegalArgumentException e) {
            v2 = rfc8410V2Fields(der);
            if (v2 == null) {
                throw e;
            }
        }

        try {
            r = importPrivate(v2[0]);
            if (!MessageDigest.isEqual(r[1], v2[1])) {
                zero(r[0]);
                zero(r[1]);
                zero(r[2]);
                throw new IllegalArgumentException(jcaName +
                    " PKCS#8 public key does not match private key");
            }
            return r;
        }
        finally {
            zero(v2[0]);
            zero(v2[1]);
        }
    }

    /**
     * Extract raw keys from an RFC 8410 OneAsymmetricKey v2 whose public key
     * contains the BIT STRING unused-bits octet.
     *
     * @param der PKCS#8 DER
     *
     * @return {@code [0]} raw private key, {@code [1]} raw public key, or
     *         null if the DER is not that form
     */
    private byte[][] rfc8410V2Fields(byte[] der) {

        int[] tk;
        int off;
        int len;
        int pubIdx;

        try {
            tk = Asn.getPkcs8TraditionalOffset(der);
        }
        catch (WolfCryptException e) {
            return null;
        }
        off = tk[0];
        len = tk[1];

        /* AlgorithmIdentifier SEQUENCE { OID 1.3.101.x } directly precedes
         * the 2-byte OCTET STRING header of the CurvePrivateKey and must
         * name this curve */
        byte[] algId = new byte[] {
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            (this == ED25519) ? (byte)0x70 : (byte)0x71
        };
        int algIdEnd = off - 2;
        int algIdStart = algIdEnd - algId.length;

        /* CurvePrivateKey: OCTET STRING holding the raw private key */
        if (len != privateKeySize + 2 || algIdStart < 0 ||
            off + len > der.length || der[off] != 0x04 ||
            (der[off + 1] & 0xff) != privateKeySize ||
            !Arrays.equals(algId,
                Arrays.copyOfRange(der, algIdStart, algIdEnd))) {
            return null;
        }

        /* publicKey [1] IMPLICIT BIT STRING is the last element: tag,
         * length and 0x00 unused bits, then the raw public key */
        int pubHdr = 3;
        pubIdx = der.length - publicKeySize - pubHdr;
        if (pubIdx < off + len || (der[pubIdx] & 0xff) != 0x81 ||
            (der[pubIdx + 1] & 0xff) != publicKeySize + 1 ||
            der[pubIdx + 2] != 0x00) {
            return null;
        }

        return new byte[][] {
            Arrays.copyOfRange(der, off + 2, off + 2 + privateKeySize),
            Arrays.copyOfRange(der, pubIdx + pubHdr, der.length)
        };
    }

    /**
     * Decode a PKCS#8 DER, export the raw keys and the canonical PKCS#8 v1
     * re-encoding.
     *
     * @param der PKCS#8 DER
     *
     * @return {@code [0]} raw private key, {@code [1]} raw public key,
     *         {@code [2]} canonical PKCS#8 v1 DER
     *
     * @throws IllegalArgumentException if native rejects the DER or the
     *         curve is not compiled in
     */
    private byte[][] decodePkcs8Native(byte[] der)
        throws IllegalArgumentException {

        if (this == ED25519) {
            Ed25519 k = null;
            try {
                k = new Ed25519();
                k.importPrivateKeyDer(der);
                return new byte[][] {
                    k.exportPrivateOnly(), k.exportPublic(),
                    k.exportPrivateKeyDer()
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed25519 PKCS#8 key: " + e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
        else {
            Ed448 k = null;
            try {
                k = new Ed448();
                k.importPrivateKeyDer(der);
                return new byte[][] {
                    k.exportPrivateOnly(), k.exportPublic(),
                    k.exportPrivateKeyDer()
                };
            }
            catch (WolfCryptException | IllegalStateException e) {
                throw new IllegalArgumentException(
                    "Invalid Ed448 PKCS#8 key: " + e.getMessage(), e);
            }
            finally {
                if (k != null) {
                    k.releaseNativeStruct();
                }
            }
        }
    }

    /**
     * Zero input byte array.
     *
     * @param b array to zero
     */
    static void zero(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte)0);
        }
    }
}
