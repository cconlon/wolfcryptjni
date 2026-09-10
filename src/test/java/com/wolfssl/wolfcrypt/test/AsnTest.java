/* AsnTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

import org.junit.Assume;
import org.junit.Test;
import org.junit.BeforeClass;

import com.wolfssl.wolfcrypt.Asn;
import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * Unit tests for Asn class, particularly dynamic OID retrieval
 */
public class AsnTest {

    @BeforeClass
    public static void checkAvailability() {
        try {
            /* Force initialization of Asn class static variables */
            int md5 = Asn.MD5h;
        } catch (UnsatisfiedLinkError ule) {
            /* wolfCrypt JNI library not found, skip tests */
            System.out.println("wolfCrypt JNI library not found, " +
                               "skipping tests");
            org.junit.Assume.assumeTrue(false);
        }
    }

    @Test
    public void testDynamicOIDRetrieval() {

        /* Test that all OID constants are initialized to non-zero values.
         * The new dynamic system should return proper hash-based OID values
         * from native wolfSSL, not the old hard-coded values. */

        assertNotEquals("MD5h should not be zero", 0, Asn.MD5h);
        assertNotEquals("SHAh should not be zero", 0, Asn.SHAh);
        assertNotEquals("SHA224h should not be zero", 0, Asn.SHA224h);
        assertNotEquals("SHA256h should not be zero", 0, Asn.SHA256h);
        assertNotEquals("SHA384h should not be zero", 0, Asn.SHA384h);
        assertNotEquals("SHA512h should not be zero", 0, Asn.SHA512h);
        assertNotEquals("SHA3_224h should not be zero", 0, Asn.SHA3_224h);
        assertNotEquals("SHA3_256h should not be zero", 0, Asn.SHA3_256h);
        assertNotEquals("SHA3_384h should not be zero", 0, Asn.SHA3_384h);
        assertNotEquals("SHA3_512h should not be zero", 0, Asn.SHA3_512h);
        assertNotEquals("ED25519k should not be zero", 0, Asn.ED25519k);
        assertNotEquals("ED448k should not be zero", 0, Asn.ED448k);
        assertNotEquals("ED25519k and ED448k must differ", Asn.ED25519k,
            Asn.ED448k);
    }

    @Test
    public void testOIDEncodingWithNewValues() {

        /* Test that the new OID values produce valid DER encodings.
         * Valid encodings should have length > 40 and proper structure. */

        byte[] digest = new byte[32];
        byte[] encoded = new byte[512];

        /* Test SHA-256 encoding */
        long encodedLength = Asn.encodeSignature(encoded, digest,
                                                 digest.length, Asn.SHA256h);
        assertTrue("SHA-256 encoding should be successful", encodedLength > 40);
        assertTrue("SHA-256 encoding should be reasonable length",
                   encodedLength < 100);

        /* Check basic DER structure */
        assertEquals("First byte should be SEQUENCE tag", 0x30,
                     encoded[0] & 0xFF);
        assertTrue("SEQUENCE length should be reasonable",
                   (encoded[1] & 0xFF) > 30);
        assertEquals("Algorithm ID should be SEQUENCE", 0x30,
                     encoded[2] & 0xFF);

        /* Test SHA-1 encoding */
        encodedLength = Asn.encodeSignature(encoded, digest, digest.length,
                                            Asn.SHAh);
        assertTrue("SHA-1 encoding should be successful", encodedLength > 40);
        assertTrue("SHA-1 encoding should be reasonable length",
                   encodedLength < 100);

        /* Test MD5 encoding */
        encodedLength = Asn.encodeSignature(encoded, digest, digest.length,
                                            Asn.MD5h);
        assertTrue("MD5 encoding should be successful", encodedLength > 40);
        assertTrue("MD5 encoding should be reasonable length",
                   encodedLength < 100);
    }

    @Test
    public void testEncodeSignatureRejectsBadSizes() {

        byte[] hash = new byte[32];

        /* Undersized output array should be rejected, not overflowed */
        byte[] tinyOut = new byte[4];
        assertTrue("undersized output array should be rejected",
                   Asn.encodeSignature(tinyOut, hash, hash.length,
                                       Asn.SHA256h) < 0);

        /* hashSize larger than hash array should be rejected, not overread */
        byte[] out = new byte[512];
        assertTrue("hashSize > hash.length should be rejected",
                   Asn.encodeSignature(out, hash, hash.length + 100,
                                       Asn.SHA256h) < 0);

        /* Negative hashSize should be rejected, not cast to huge word32 */
        assertTrue("negative hashSize should be rejected",
                   Asn.encodeSignature(out, hash, -1, Asn.SHA256h) < 0);

        /* Properly sized buffers should still succeed */
        assertTrue("valid sizes should still encode",
                   Asn.encodeSignature(out, hash, hash.length,
                                       Asn.SHA256h) > 0);
    }

    @Test
    public void testEncodeSignatureByteBufferRejectsBadSizes() {

        ByteBuffer hash = ByteBuffer.allocateDirect(32);

        /* Undersized output buffer should be rejected, not overflowed */
        ByteBuffer tinyOut = ByteBuffer.allocateDirect(4);
        try {
            Asn.encodeSignature(tinyOut, hash, hash.limit(), Asn.SHA256h);
            fail("undersized output buffer should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* hashSize larger than hash buffer should be rejected */
        ByteBuffer out = ByteBuffer.allocateDirect(512);
        try {
            Asn.encodeSignature(out, hash, hash.limit() + 100, Asn.SHA256h);
            fail("hashSize > hash.limit() should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Negative hashSize should be rejected */
        try {
            Asn.encodeSignature(out, hash, -1, Asn.SHA256h);
            fail("negative hashSize should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Properly sized buffers should still succeed */
        out.limit(out.capacity());
        Asn.encodeSignature(out, hash, hash.limit(), Asn.SHA256h);
        assertTrue("valid sizes should still encode", out.limit() > 0);
    }

    @Test
    public void testOIDUniqueness() {

        /* Test that all OID values are unique.
         * Each algorithm should have a distinct OID value. */

        int[] oids = {
            Asn.MD5h, Asn.SHAh, Asn.SHA224h, Asn.SHA256h, Asn.SHA384h,
            Asn.SHA512h, Asn.SHA3_224h, Asn.SHA3_256h, Asn.SHA3_384h,
            Asn.SHA3_512h
        };

        /* Check that all values are unique */
        for (int i = 0; i < oids.length; i++) {
            for (int j = i + 1; j < oids.length; j++) {
                assertNotEquals("OID values should be unique", oids[i],
                                oids[j]);
            }
        }
    }

    /* RFC 8410 section 10.3 example: Ed25519 OneAsymmetricKey v2 with an
     * attributes [0] element and a publicKey [1] element following the
     * CurvePrivateKey */
    private static final String RFC8410_V2_EXAMPLE =
        "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" +
        "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" +
        "Z9w7lshQhqowtrbLDFw4rXAxZuE=";

    /* private key octets from the RFC 8410 section 10.3 example */
    private static final byte[] RFC8410_PRIV = Util.h2b(
        "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");

    /* Skip when native wolfSSL was built without PKCS#8 support */
    private static void assumePkcs8(byte[] der) {
        try {
            Asn.getPkcs8AlgoID(der);
        } catch (WolfCryptException e) {
            Assume.assumeTrue("PKCS#8 not compiled in",
                e.getError() != WolfCryptError.NOT_COMPILED_IN);
        }
    }

    @Test
    public void testGetPkcs8TraditionalOffsetRfc8410Example() {

        Assume.assumeTrue("Ed25519 not compiled in",
            FeatureDetect.Ed25519Enabled());

        byte[] der = Base64.getDecoder().decode(RFC8410_V2_EXAMPLE);
        assumePkcs8(der);

        int[] tk = Asn.getPkcs8TraditionalOffset(der);
        assertEquals(2, tk.length);
        /* SEQUENCE(2) + version(3) + AlgorithmIdentifier(7) + OCTET STRING
         * header(2) puts the CurvePrivateKey at offset 14. It is the 34-byte
         * OCTET STRING { 32-byte private key } regardless of attributes and
         * public key that follow it */
        assertEquals(14, tk[0]);
        assertEquals(34, tk[1]);
        assertEquals(0x04, der[tk[0]]);
        assertEquals(0x20, der[tk[0] + 1]);
        assertArrayEquals(RFC8410_PRIV,
            Arrays.copyOfRange(der, tk[0] + 2, tk[0] + tk[1]));
        /* input must not have been modified */
        assertArrayEquals(Base64.getDecoder().decode(RFC8410_V2_EXAMPLE), der);
    }

    @Test
    public void testGetPkcs8TraditionalOffsetV1() throws Exception {

        Assume.assumeTrue("Ed25519 not compiled in",
            FeatureDetect.Ed25519Enabled());

        Rng rng = new Rng();
        Ed25519 key = new Ed25519();
        byte[] der;
        byte[] rawPriv;

        try {
            rng.init();
            key.makeKey(rng);
            der = key.exportPrivateKeyDer();
            rawPriv = key.exportPrivateOnly();
        } finally {
            key.releaseNativeStruct();
            rng.releaseNativeStruct();
        }
        assumePkcs8(der);

        int[] tk = Asn.getPkcs8TraditionalOffset(der);
        assertEquals(14, tk[0]);
        assertEquals(34, tk[1]);
        assertEquals(0x04, der[tk[0]]);
        assertEquals(0x20, der[tk[0] + 1]);
        assertArrayEquals(rawPriv,
            Arrays.copyOfRange(der, tk[0] + 2, tk[0] + tk[1]));
    }

    @Test
    public void testGetPkcs8TraditionalOffsetBadInput() {

        byte[] der = Base64.getDecoder().decode(RFC8410_V2_EXAMPLE);
        assumePkcs8(der);

        try {
            Asn.getPkcs8TraditionalOffset(null);
            fail("null input accepted");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            Asn.getPkcs8TraditionalOffset(new byte[0]);
            fail("empty input accepted");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            Asn.getPkcs8TraditionalOffset(new byte[] { 0x01, 0x02, 0x03 });
            fail("garbage input accepted");
        } catch (WolfCryptException e) {
            /* expected */
        }
        /* truncated PKCS#8 */
        try {
            Asn.getPkcs8TraditionalOffset(Arrays.copyOf(der, 20));
            fail("truncated input accepted");
        } catch (WolfCryptException e) {
            /* expected */
        }
        /* well formed envelope with an empty privateKey OCTET STRING */
        try {
            Asn.getPkcs8TraditionalOffset(Util.h2b(
                "300d020100300506032b65700400"));
            fail("empty private key accepted");
        } catch (WolfCryptException e) {
            /* expected */
        }
    }
}
