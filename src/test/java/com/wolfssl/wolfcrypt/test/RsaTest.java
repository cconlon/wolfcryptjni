/* RsaTest.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.Random;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class RsaTest {
    private static Rng rng = new Rng();

    @BeforeClass
    public static void setUpRng() {
        rng.init();
    }

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Rsa();
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("Rsa test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldInitializeNativeStruct() {
        assertNotEquals(NativeStruct.NULL, new Rsa().getNativeStruct());
    }

    @Test
    public void testMakeKey() {

        Rsa key = null;

        /* FIPS after 2425 doesn't allow 1024-bit RSA key gen */
        if (Fips.enabled && Fips.fipsVersion < 5) {
            key = new Rsa();
            key.makeKey(1024, 65537, rng);
            key.releaseNativeStruct();
        }

        key = new Rsa();
        key.makeKey(2048, 65537, rng);
        key.releaseNativeStruct();

        key = new Rsa();
        key.makeKey(3072, 65537, rng);
        key.releaseNativeStruct();

        key = new Rsa();
        key.makeKey(4096, 65537, rng);
        key.releaseNativeStruct();
    }

    @Test
    public void testDerExportImportSignVerify() {

        /* generate new 2048-bit key */
        Rsa key = new Rsa();
        key.makeKey(2048, 65537, rng);

        /* export key to DER */
        byte[] rsaDer = key.exportPrivateDer();
        assertNotNull(rsaDer);
        assertTrue(rsaDer.length > 0);
        key.releaseNativeStruct();

        /* try to re-import DER into new Rsa object */
        key = new Rsa();
        key.decodePrivateKey(rsaDer);

        /* sign data */
        byte[] data = "Hello wolfSSL".getBytes();
        byte[] signed = key.sign(data, rng);

        /* verify data matches original */
        byte[] verify = key.verify(signed);
        assertNotNull(verify);
        assertArrayEquals(data, verify);

        key.releaseNativeStruct();
    }

    @Test
    public void rsaPrivateToPkcs8() {
        Rsa key = new Rsa();
        byte[] pkcs8;
        int size;
        byte[] prvKey = Util.h2b(
                "308204a40201000282010100c303d12bfe39a432453b53c8842b2a7c"
              + "749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed48148"
              + "fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e"
              + "7b9b03479abf65cc7f652469a6e814895be434f7c5b01493f567"
              + "7b3a7a78e101565691a613428dd23c409c4cefd186df37511b0c"
              + "a13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081af20"
              + "0b4314c57467b432826f8d86c28840993683ba1e40722217d752"
              + "652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba33ba3"
              + "995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179f471"
              + "d386401813b063b5724e30c49784862d562fd715f77fc0aef5fc"
              + "5be5fba1bad302030100010282010100a2e6d85f107164089e2e"
              + "6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
              + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e"
              + "0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2eee0"
              + "1ea1f4be97db86639614cd9809602d30769c3ccde688ee479279"
              + "0b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3bc24"
              + "a95e260e1f002dfe219a535b6dd32bab9482684336d8f62fc622"
              + "fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172faade"
              + "e99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c960c"
              + "fa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450e417"
              + "3948d0358b946d11de8fca5902818100ea24a7f96933e971dc52"
              + "7d8821282f49deba7216e9cc477a880d94578458163a81b03fa2"
              + "cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38"
              + "900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8da757"
              + "6c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b24dba"
              + "30da478f54d33d8b848d949858a502818100d5381bc38fc5930c"
              + "470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52abaca"
              + "18b05da507d0938dd89c041cd4628ea6268101ffce8a2a633435"
              + "40aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae273d"
              + "de4ef0aac56c78676c94529c37676c2defbbafdfa6903cc447cf"
              + "8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba7c"
              + "a2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e"
              + "766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f"
              + "5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc"
              + "16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a753a4b"
              + "efc73c3ef7fd26b820c4990a9a73bec31902818100ba449314ac"
              + "34193b5f9160acf7b4d681053651533de865dcaf2edc613ec97d"
              + "b87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d7fec"
              + "79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d899c0"
              + "11205d0f29fd5be2aed91cd921566dfc84d05fed10151c1821e7"
              + "c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
              + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3"
              + "c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e3"
              + "2da3750d1e4d2134d557705c89bf72ec4a6e68d5cd1874334e8c"
              + "3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538be35"
              + "abca5ce7935334a1455d1339654246a19fcdf5bf");

        byte[] expectedPkcs8 = Util.h2b(
                "308204be020100300d06092a864886f70d0101010500048204a8"
              + "308204a40201000282010100c303d12bfe39a432453b53c8842b"
              + "2a7c749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed4"
              + "8148fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1"
              + "811e7b9b03479abf65cc7f652469a6e814895be434f7c5b01493"
              + "f5677b3a7a78e101565691a613428dd23c409c4cefd186df3751"
              + "1b0ca13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081"
              + "af200b4314c57467b432826f8d86c28840993683ba1e40722217"
              + "d752652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba3"
              + "3ba3995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179"
              + "f471d386401813b063b5724e30c49784862d562fd715f77fc0ae"
              + "f5fc5be5fba1bad302030100010282010100a2e6d85f10716408"
              + "9e2e6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea"
              + "597bf277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872"
              + "172e0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2"
              + "eee01ea1f4be97db86639614cd9809602d30769c3ccde688ee47"
              + "92790b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3"
              + "bc24a95e260e1f002dfe219a535b6dd32bab9482684336d8f62f"
              + "c622fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172f"
              + "aadee99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c"
              + "960cfa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450"
              + "e4173948d0358b946d11de8fca5902818100ea24a7f96933e971"
              + "dc527d8821282f49deba7216e9cc477a880d94578458163a81b0"
              + "3fa2cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052ae"
              + "fc38900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8d"
              + "a7576c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b2"
              + "4dba30da478f54d33d8b848d949858a502818100d5381bc38fc5"
              + "930c470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52a"
              + "baca18b05da507d0938dd89c041cd4628ea6268101ffce8a2a63"
              + "343540aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae"
              + "273dde4ef0aac56c78676c94529c37676c2defbbafdfa6903cc4"
              + "47cf8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bd"
              + "ba7ca2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f3"
              + "5f0e766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6"
              + "624f5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6"
              + "fcfc16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a75"
              + "3a4befc73c3ef7fd26b820c4990a9a73bec31902818100ba4493"
              + "14ac34193b5f9160acf7b4d681053651533de865dcaf2edc613e"
              + "c97db87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d"
              + "7fec79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d8"
              + "99c011205d0f29fd5be2aed91cd921566dfc84d05fed10151c18"
              + "21e7c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d0"
              + "4bcf1b67b99f1075478665ae31c2c630ac590650d90fb57006f7"
              + "f0d3c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c230"
              + "37e32da3750d1e4d2134d557705c89bf72ec4a6e68d5cd187433"
              + "4e8c3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538"
              + "be35abca5ce7935334a1455d1339654246a19fcdf5bf");

        /* FIPS after 2425 doesn't allow 1024-bit RSA key gen */
        if (Fips.enabled && Fips.fipsVersion >= 5) {
            /* skip */
            return;
        }

        /* Test that exception is thrown without private key available */
        try {
            pkcs8 = key.privateKeyEncodePKCS8();
            fail("Rsa.privateKeyEncodePKCS8() should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* Test that encoded PKCS#8 private key matches expected */
        key.decodePrivateKey(prvKey);
        pkcs8 = key.privateKeyEncodePKCS8();
        assertArrayEquals(pkcs8, expectedPkcs8);
        key.releaseNativeStruct();

        /* Test that generated key encodes without error */
        key = new Rsa();
        key.makeKey(1024, 65537, rng);
        pkcs8 = key.privateKeyEncodePKCS8();
        assertTrue(pkcs8 != null);
        assertTrue(pkcs8.length != 0);
        key.releaseNativeStruct();
    }

    @Test
    public void publicKeyDecodeAndEncodeWithByteBuffer() {
        Rsa key = new Rsa();

        ByteBuffer n_in = ByteBuffer.allocateDirect(256);
        ByteBuffer e_in = ByteBuffer.allocateDirect(256);
        ByteBuffer n_out = ByteBuffer.allocateDirect(256);
        ByteBuffer e_out = ByteBuffer.allocateDirect(256);

        n_in.put(Util
                .h2b("aff5f9e2e2622320d44dbf54f2274a0f96fa7d70a63ddaa563f48811"
                        + "43112bb3c36fe65ba0c9ad99d6fb6e53cb08e3938ee415b3a8cb"
                        + "7f9602f2154fab83dd160fa6f509ba2c41295af9eea8787d333e"
                        + "961461447fc60b3c61616ef5b94e822114e6fad44d1f2c476bc2"
                        + "3bc03609e2e70a483d826409fdb7c50a91269a773976ef137e7f"
                        + "a477c3951e8fbcb48f2378aa5e430e8c60b481beeb63df9abe10"
                        + "c7ccf266e394fbd925e8725e4675fb6ad895caed4b31d751c871"
                        + "2533e1c42ebefe9166e1aa20631521858c7548c61626ede105f2"
                        + "812632bac96eb769c9be560beef4200b86409727a5a61d1cc583"
                        + "1785ba4d42f02dd298a56bbbd6c479ce724d5bb5"))
                .rewind();
        e_in.put(Util.h2b("d0ee61")).rewind();

        key.decodeRawPublicKey(n_in, e_in);
        key.exportRawPublicKey(n_out, e_out);

        assertEquals(n_in, n_out);
        assertEquals(e_in, e_out);
    }

    @Test
    public void publicKeyDecodeAndEncodeWithByteArray() {
        Rsa key = new Rsa();

        byte[] n_in = Util
                .h2b("aff5f9e2e2622320d44dbf54f2274a0f96fa7d70a63ddaa563f48811"
                        + "43112bb3c36fe65ba0c9ad99d6fb6e53cb08e3938ee415b3a8cb"
                        + "7f9602f2154fab83dd160fa6f509ba2c41295af9eea8787d333e"
                        + "961461447fc60b3c61616ef5b94e822114e6fad44d1f2c476bc2"
                        + "3bc03609e2e70a483d826409fdb7c50a91269a773976ef137e7f"
                        + "a477c3951e8fbcb48f2378aa5e430e8c60b481beeb63df9abe10"
                        + "c7ccf266e394fbd925e8725e4675fb6ad895caed4b31d751c871"
                        + "2533e1c42ebefe9166e1aa20631521858c7548c61626ede105f2"
                        + "812632bac96eb769c9be560beef4200b86409727a5a61d1cc583"
                        + "1785ba4d42f02dd298a56bbbd6c479ce724d5bb5");
        byte[] e_in = Util.h2b("d0ee61");
        byte[] n_out = new byte[n_in.length];
        byte[] e_out = new byte[e_in.length];
        long[] n_len = new long[1];
        long[] e_len = new long[1];

        n_len[0] = n_out.length;
        e_len[0] = e_out.length;

        key.decodeRawPublicKey(n_in, e_in);
        key.exportRawPublicKey(n_out, n_len, e_out, e_len);

        assertArrayEquals(n_in, n_out);
        assertArrayEquals(e_in, e_out);
    }

    @Test
    public void rsaOperations() {
        Rsa priv = new Rsa(Util
                .h2b("308204a40201000282010100c303d12bfe39a432453b53c8842b2a7c"
                        + "749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed48148"
                        + "fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e"
                        + "7b9b03479abf65cc7f652469a6e814895be434f7c5b01493f567"
                        + "7b3a7a78e101565691a613428dd23c409c4cefd186df37511b0c"
                        + "a13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081af20"
                        + "0b4314c57467b432826f8d86c28840993683ba1e40722217d752"
                        + "652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba33ba3"
                        + "995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179f471"
                        + "d386401813b063b5724e30c49784862d562fd715f77fc0aef5fc"
                        + "5be5fba1bad302030100010282010100a2e6d85f107164089e2e"
                        + "6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
                        + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e"
                        + "0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2eee0"
                        + "1ea1f4be97db86639614cd9809602d30769c3ccde688ee479279"
                        + "0b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3bc24"
                        + "a95e260e1f002dfe219a535b6dd32bab9482684336d8f62fc622"
                        + "fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172faade"
                        + "e99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c960c"
                        + "fa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450e417"
                        + "3948d0358b946d11de8fca5902818100ea24a7f96933e971dc52"
                        + "7d8821282f49deba7216e9cc477a880d94578458163a81b03fa2"
                        + "cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38"
                        + "900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8da757"
                        + "6c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b24dba"
                        + "30da478f54d33d8b848d949858a502818100d5381bc38fc5930c"
                        + "470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52abaca"
                        + "18b05da507d0938dd89c041cd4628ea6268101ffce8a2a633435"
                        + "40aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae273d"
                        + "de4ef0aac56c78676c94529c37676c2defbbafdfa6903cc447cf"
                        + "8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba7c"
                        + "a2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e"
                        + "766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f"
                        + "5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc"
                        + "16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a753a4b"
                        + "efc73c3ef7fd26b820c4990a9a73bec31902818100ba449314ac"
                        + "34193b5f9160acf7b4d681053651533de865dcaf2edc613ec97d"
                        + "b87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d7fec"
                        + "79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d899c0"
                        + "11205d0f29fd5be2aed91cd921566dfc84d05fed10151c1821e7"
                        + "c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
                        + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3"
                        + "c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e3"
                        + "2da3750d1e4d2134d557705c89bf72ec4a6e68d5cd1874334e8c"
                        + "3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538be35"
                        + "abca5ce7935334a1455d1339654246a19fcdf5bf"));

        byte[] n_out = new byte[256];
        byte[] e_out = new byte[3];
        long[] n_len = new long[1];
        long[] e_len = new long[1];
        n_len[0] = n_out.length;
        e_len[0] = e_out.length;

        priv.exportRawPublicKey(n_out, n_len, e_out, e_len);
        priv.setRng(rng);

        Rsa pub = new Rsa(n_out, e_out);

        byte[] plaintext = "Now is the time for all".getBytes();

        byte[] ciphertext = pub.encrypt(plaintext, rng);

        assertArrayEquals(plaintext, priv.decrypt(ciphertext));

        byte[] signature = priv.sign(plaintext, rng);

        assertArrayEquals(plaintext, pub.verify(signature));
    }

    @Test
    public void threadedRsaSignVerifyTest() throws InterruptedException {

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();

        final byte[] prvKey = Util
                .h2b("308204a40201000282010100c303d12bfe39a432453b53c8842b2a7c"
                        + "749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed48148"
                        + "fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e"
                        + "7b9b03479abf65cc7f652469a6e814895be434f7c5b01493f567"
                        + "7b3a7a78e101565691a613428dd23c409c4cefd186df37511b0c"
                        + "a13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081af20"
                        + "0b4314c57467b432826f8d86c28840993683ba1e40722217d752"
                        + "652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba33ba3"
                        + "995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179f471"
                        + "d386401813b063b5724e30c49784862d562fd715f77fc0aef5fc"
                        + "5be5fba1bad302030100010282010100a2e6d85f107164089e2e"
                        + "6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
                        + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e"
                        + "0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2eee0"
                        + "1ea1f4be97db86639614cd9809602d30769c3ccde688ee479279"
                        + "0b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3bc24"
                        + "a95e260e1f002dfe219a535b6dd32bab9482684336d8f62fc622"
                        + "fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172faade"
                        + "e99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c960c"
                        + "fa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450e417"
                        + "3948d0358b946d11de8fca5902818100ea24a7f96933e971dc52"
                        + "7d8821282f49deba7216e9cc477a880d94578458163a81b03fa2"
                        + "cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38"
                        + "900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8da757"
                        + "6c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b24dba"
                        + "30da478f54d33d8b848d949858a502818100d5381bc38fc5930c"
                        + "470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52abaca"
                        + "18b05da507d0938dd89c041cd4628ea6268101ffce8a2a633435"
                        + "40aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae273d"
                        + "de4ef0aac56c78676c94529c37676c2defbbafdfa6903cc447cf"
                        + "8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba7c"
                        + "a2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e"
                        + "766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f"
                        + "5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc"
                        + "16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a753a4b"
                        + "efc73c3ef7fd26b820c4990a9a73bec31902818100ba449314ac"
                        + "34193b5f9160acf7b4d681053651533de865dcaf2edc613ec97d"
                        + "b87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d7fec"
                        + "79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d899c0"
                        + "11205d0f29fd5be2aed91cd921566dfc84d05fed10151c1821e7"
                        + "c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
                        + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3"
                        + "c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e3"
                        + "2da3750d1e4d2134d557705c89bf72ec4a6e68d5cd1874334e8c"
                        + "3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538be35"
                        + "abca5ce7935334a1455d1339654246a19fcdf5bf");

        final byte[] plaintext = "Now is the time for all".getBytes();

        /* Do encrypt/decrypt and sign/verify in parallel across numThreads
         * threads, all operations should pass */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int failed = 0;

                    Rsa priv = null;
                    Rsa pub = null;

                    byte[] n_out = new byte[256];
                    byte[] e_out = new byte[3];
                    long[] n_len = new long[1];
                    long[] e_len = new long[1];
                    n_len[0] = n_out.length;
                    e_len[0] = e_out.length;

                    try {
                        priv = new Rsa(prvKey);
                        priv.exportRawPublicKey(n_out, n_len, e_out, e_len);
                        priv.setRng(rng);

                        pub = new Rsa(n_out, e_out);

                        byte[] ciphertext = pub.encrypt(plaintext, rng);

                        if (!Arrays.equals(plaintext,
                                priv.decrypt(ciphertext))) {
                            failed = 1;
                        }

                        if (failed == 0) {
                            byte[] signature = priv.sign(plaintext, rng);

                            if (!Arrays.equals(plaintext,
                                    pub.verify(signature))) {
                                failed = 1;
                            }
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        failed = 1;

                    } finally {
                        priv.releaseNativeStruct();
                        pub.releaseNativeStruct();
                        latch.countDown();
                    }

                    if (failed == 1) {
                        results.add(1);
                    }
                    else {
                        results.add(0);
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* Look for any failures that happened */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in RSA sign/verify thread test");
            }
        }
    }
}
