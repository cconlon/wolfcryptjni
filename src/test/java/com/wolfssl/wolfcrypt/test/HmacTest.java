/* HmacTest.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.Hmac;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class HmacTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Hmac();
            System.out.println("JNI Hmac Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("Hmac test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new Hmac().getNativeStruct());
    }

    @Test
    public void shaHmacShouldMatch() {
        String[] keyVector = new String[] {
                "fd42f5044e3f70825102017f8521",
                "7da600a31369689ae60b73e30bd9",
                "c545cc0ef4adf1c98bd9e0e4ba04",
                "dc88f9f7fb295d363e9c961b2277",
                "53c07bf2870a2c70977d2ca88a12" };
        String[] dataVector = new String[] {
                "c9995cad63f60f7c7c552ac12c080a7262cec4636d47c460c2abb47af9bca09e18f9576c1415144595a75da6fa232cb59d094d1a585c07104856febcd05a58bde12a1f04795ae6e66a05b06f5dbe0dfa16c986fefa8c3b2bce40cbb6c1ec74f1ad947c1e9aadcf8584d5e9c45ec1f667567738b85bbdaad8dcd1e30fd35a3c61",
                "5ce71d286f169ad2530539f23cab645b848ae6bbf0e1507135229b9ebba6107fa0a065fa00502976747962f0d814744b524644e88f909e775046d40d2642a87679d96ccccf0e68484b067c5974bc07f339f6072a317881ff2777237ad55028f9f07a7cc765b920f0e395d154990be4fb418275a85d01c0b1c09ecf0d513a56af",
                "da59e8c582788156fad656490b2523f9f6b5c463128df7dcb6ba62ff59e7d8eaf82ed8aab92e56f3cd5ebe149aa0372b1a1a25957e41f1a918360ca6775631e9d40deb64adea584baff92c10d94df892dfdcad92cc905c66ec9a3ff1e90afdd2349c2adca6d50dc6684fa7241052f0960ca3644044a1be7afb8d04c8f62ac30c",
                "138175914830bcff738a5a5bf87473cea88bfffde5b7123b060360fcfdac008d36777003c348da72b7f1955fcf48ef77587c2a814ca9c491bfa9fc7e792e9197e50dcd922addc2c597c1d4994482773bf6e13a94442b057cf80d9e2ab8aa72efe6eb9325c416fd62dca31df19f4b94824c61382013655b647bd751e801492cff",
                "ccf6c4e78395e3dbf5903a42c74ea356d293e59e18a53d28fdae3e14b462dc52f7e1c3abfbdfed06a30273e4f48ba32ec9395430c76a76e59484ed754493a0fc1434cc8d5bb19f77bd6d02c6a283b60de6aaa263d35c6bac4c37461a4aa30af38db58a948b5321b6ad998ef0ba7c027d93ad784022c045058d8ef00aafd843be" };
        String[] hashVector = new String[] {
                "8865eb9df41dcc2e74360f0c97ae567cb2377022",
                "8fd0ff57504a60bd460cea9d1afa43bc205b77ca",
                "2d8f3f19c881a74f2a7ddf41995948d25de00c4d",
                "fad5325c63d562b0d1bbf9861cd610a30cc9f387",
                "fb6788ccd29e16544e5b52c963279b6a9eb21537" };

        for (int i = 0; i < dataVector.length; i++) {
            try {
                Hmac hmac = new Hmac();
                byte[] key = Util.h2b(keyVector[i]);
                byte[] data = Util.h2b(dataVector[i]);
                byte[] expected = Util.h2b(hashVector[i]);

                hmac.setKey(Hmac.SHA, key);

                for (byte b : data)
                    hmac.update(b);

                assertArrayEquals(expected, hmac.doFinal());

                hmac.reset();

                assertArrayEquals(expected, hmac.doFinal(data));
            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA1 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void sha256HmacShouldMatch() {
        ByteBuffer buffer = ByteBuffer.allocateDirect(128);
        String[] keyVector = new String[] {
                "26afdd2445b1f3cecbd4a797fed8",
                "14c9c8e4fa673ece90e73d9a18d1",
                "bb3c195752b24a463823d2620595",
                "db6efda716329287dce98e6ce10c",
                "30d1930c549205d9c5fdd18e9ccf" };
        String[] dataVector = new String[] {
                "bd74f8646cdd9b217927b04ef4eeef0b8ef0b78fafcabb11c202f8e8d44aeaf15d03ff315d014cbbab8e7ed48ab114567eb0cc525ed35bf9a96b61bd1d139cb386365c3cd5d137e4717afd8ad2a2efc24b172b7727cc6bd5f8ddef652cceb87ae114f7cdfbd6c56473f414b8f149e6169e2dbd46333e526b5761892a2703a50e",
                "5bf1f0debfd16f461c39f6b217cee809caceda9d0c46f503f3859c2398d04f8b1a57d009e668847835e31bdad6ee74a72de9ba657ca5d47961d0fc3da0b4ad522322c3383fa8de1b390a07f009f096c15ddd5245e160dbb4be8e45d960af06697d38129353fa44d83198001d383e17ff6390ea66c5e1d35d12a6c021612a2177",
                "62e887c3b61aa1a0dabcd8ef5b32c8646900bcb437972b05a56e83a21d5526f4ba07b2aeb0fe8647e88b82adea250d3800025ddc98e4f3a4eb36645bdc575f8c2336ecaeaa1ff29837d4fc3b4ce03c8f4c28d1cedec345e1960b5a17d3f4061de39dbc2b6e25ed7b11c0cfff490a5d53939b9ff1d1db2ba4f017ec3fc8d5228e",
                "defea353554ed885906e4908c6c784c0a171159d9d050512b2aca0c9327c7b95f405b6a8b2267f06b026d7399eff9946c0fdb8e14c88c8dd143ec0e66446fe722ee08bf56440a154a69c6a9d1d840bf5a772e1d234a20a6a7023286ba22f61ecd3b8aba334434659baf9899c0bfbe2b49df719d81cf9d4a10d8360beb2dfaeea",
                "51bae03dedf92f6b4f4e03bc354d2917fabaeee968058ec7cf11ef5553398f668a95bb64477903f3b03fead19747e200073b77281c98ca37186a414ab4577dd0b4de8cecbee1601c6c618019a08afefe18efa9ab4216836c513776d6904142f2f61eba9efb38302fab3c2e5bf91e6757555dec3c8188a3afa001f6c19001c814" };
        String[] hashVector = new String[] {
                "208661dd6bdeab1c2843dfb8226cbe0a69db31aa183004e12025039f9fc2446a",
                "e01c8940c0dec16538b8a83aa78c1e7bfb836a535c9d38a8515897f778f50ac3",
                "cfbe171836e677f91d3e357bfcfb2047812b353e0c482478da2b0805c7c5c3c1",
                "38fdd1616274346984ddbb53c03b820ba79df46ca1deaf15baab44886c1858d4",
                "e35457edf1dc47f70be1e7dfd4f2332b704a0febd0dbca26a6bb63d1c7bef647" };

        for (int i = 0; i < dataVector.length; i++) {
            try {
                byte[] data = Util.h2b(dataVector[i]);
                byte[] expected = Util.h2b(hashVector[i]);
                Hmac hmac = new Hmac();

                hmac.setKey(Hmac.SHA256, Util.h2b(keyVector[i]));
                hmac.update(data);

                assertArrayEquals(expected, hmac.doFinal());

                assertEquals(expected.length, hmac.getMacLength());

                hmac.reset();

                buffer.put(data).rewind();
                hmac.update(buffer);
                buffer.rewind();

                assertArrayEquals(expected, hmac.doFinal());
            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA256 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void sha384HmacShouldMatch() {
        String[] keyVector = new String[] {
                "d35d6a733af2947fbdb4a67f5b3d",
                "d01363d83fe6cf28d7c769e1529f",
                "fe003886ae2a4adf38153367126c",
                "3d82f686042a40193035be076ea2",
                "0b52f9bfaece97f12f44876c1d99" };
        String[] dataVector = new String[] {
                "44a8e36ec9b42a94a9627bd391f7114dad4296d31c3639a8a1d801889b5c61e9378a0c81e4670a0807120c3ff0ecfd310dfbd9b95e91c244292851d8ef912a569e4ed3fc083cc62d9475c47534746dc8977a0e0a9f31bad5158f9c769cfe8b38e3badfe61f7a838bb9524c7c43d88998b186dccfc65f48e1ccd58a6888ebad19",
                "f2a4a978e6bcc831bc733668d43bf528d8a0ad8d45c34cd9270aefc524160515bbf5b16fce99716d5e89fef197d773b90c52b03343fc019274bffb218e5ba7d77ba3e32ca5e9042cb9b7c0caabc04c76fa15c1f2359cc461bebf66a1ce6149dab91605577393c9955363469a18dcc8882a52a672228add6e8b71f8ecea0e3346",
                "fdb6f1f9e67e49211f046ed3e94ddbedb3de99a7ee36b22e1d9de98f2b1ca8d702cd3a7859553aefcdae4ca4342a0b122eb44227fc595eee9608236bf7969fc7bc055caded06daf31bbc3c7dabc3425e71717741815cac08411ca4b2c352118252e9bf5d4b9b10752fb7a824f522691aa59ca2bb224583c34760d52c3656e851",
                "02b36e465457f599e15b2a7df333beace7122b88290a475f607619ede595ec227a77a326391d4c9bcadcf822d902c920c7bc4cc2a037093e4e06595c0cc478361dfadb3bbd42c47a58ad131efa635f34078945b52c6800c095cb3a2760a8222d5203bf8ec91084c0f29824793c9da8710d41be69b3e4546c9d8d6555cb8b1391",
                "261a007d2c9a16c112174e4539c12c525db95faac574960ebc61950345cb88d60b0097de97b3ba01c59fcf79796dead88ed8ec4a0f0f571baa5a60796101467a836ae361db81811d275cee12cc20d31cc71e41d1e7428d0739ae5e97c4a20460779f0b8e60cc101c1f98d49799a18f25f1d587c7b4d6e0db53a3b6e5d776698e" };
        String[] hashVector = new String[] {
                "346ff5f9b77866d72154b6b6965f1f56e7c21ddf3392bdbe12e5dffb1d75e2f0d919c1e133c83b9b56d317c3db1364de",
                "b4eac786a8c3b28f3f71d511f1853b4ea4a014555c2276ed9c1024f93806ac169b7838ac763c7dfe8626090e4c247966",
                "b3faceb4a12e425452b238fa46650b27581ed8c8b2d58b45ed4286e8e6591a427457d2b1a8552b4452af65726a99c3f9",
                "57bf17e90551367365ef26363908df21415550733591090d4132e736f9d676c2770763de9819a454acd05fa01d03658e",
                "914551534846b871c2c70d5e30856021c2b1ff7490354e987423069db694de2f1e960ae84b341c2a0bf5301f7bc77ade" };

        for (int i = 0; i < dataVector.length; i++) {
            try {
                Hmac hmac = new Hmac();
                byte[] key = Util.h2b(keyVector[i]);
                byte[] data = Util.h2b(dataVector[i]);
                byte[] expected = Util.h2b(hashVector[i]);

                hmac.setKey(Hmac.SHA384, key);

                /* first half */
                hmac.update(data, 0, data.length / 2);

                /* second half */
                hmac.update(data, data.length / 2, data.length / 2);

                assertArrayEquals(expected, hmac.doFinal());

                assertEquals("HmacSHA384", hmac.getAlgorithm());

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA384 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void sha512HmacShouldMatch() {
        String[] keyVector = new String[] {
                "c3ec1135bb477eb81ca421deb9e0",
                "b3ced81bdbf1ddfda2993358c3e3",
                "c894ba1740f6719df065ec0f2f26",
                "bc7cd7e0a622f2a845a58bb8c54e",
                "5811186294384ff380da7e6d4057" };
        String[] dataVector = new String[] {
                "837dbbb0371bf60082c788c8f16ff883dd9216d235f7decf7ea09f9e17fa5d46c25673bf609c7c4dfc3e740c0b6c1bcbf2879a1dc9d769ae5f8070d47eb26d66702195d1c1b57e6847823cfc60facbad7b61adffda82d33196a1c1cae3b0ee7495c6690de3ccc2fc6b7a28c17782cfd07f0a95a0ef60e4ff29e9daa8ce5ba717",
                "348aaa54e95f8ad82e578d4c9bfa2c158c7dd8b11de78ef75272ac9f9534030466fe2d294e8520fa14bf04d5349042498da6de1e5aa206956378ebf07518cf350f4e5f305ee644b76b15f5329414cf5a390e6740b73c1f919a4ff7190e0ea6879740ea7002cc1c969c1f0769a1cefacef77c1c201cff00745ebe79224a5db081",
                "48cf0f4280310e15dce9cb762ecccf9b6c4ed919625a2df0a4812ec8c7572f7ad01a87d2ed95e3946344e1bcc8b9da0a723efebe2fbca7a136dce7445e6b638c8e03656e75e82cf87b308791f727a281a2f11fb44c7168bacd6a44133fe4a9aa6ad2d29f80f190490bf3e57c23ddcf07e4ae62811f41194650746ebcd08aa8db",
                "ce7ed6c4893b0e0c1f6fd4d7a76399e3b2f122f1d2f42dd35dfd57c76e483d032deee291505b515de203838d4351821071e0cf7a85ee010f810eb01d481c9190ee76e2c03269098d49ea78aede87d346569d55b858ca70bd8da5b3b4a4adf1399a80a0f8384e7fc3dd8c7ce37dedd4acea8e7c555270c006092c2a3189e2a526",
                "6499093b13730ad3ba7174a553b8af0a2481d935e7b50e6527bbe75fed8d401c9c123fbf1aa892ca30fff790342e02eee5001b36968fc66c8f1527b5b0fec50c57428e3784f11bf93b10368a2aa399448c0bf99f4d92435f6f45260cac02d1a35dd1fe8b9a772fcaa34937797e3ffd75e2497d5854e60fa890f2ec4e2abfee49" };
        String[] hashVector = new String[] {
                "517bd0146fe52cb464a0d555a7c29b5f9a604b07f32ff255f139156e214b6eb3836aa089987a5aca585e3cb10af8cb19c12a89628e8f59b6952ac4b7da7131f0",
                "36ae3af119a0aa779b6d259733033da52b6afa875a54076da039329fa35177a55d1748a70919f9f6bc962349989d033c64f483c9c42165e7698bca05cee264d5",
                "ae0c864d2d55245d92c28962abefe839a29a5b7e7804986548a792fa8985d008bb300e82da199abcef20407775306d2d95c0fc486a75508b0421ea8480838e75",
                "fc0dfe0e7f76ba0fa7d5fa2321efcc83d03f2963c050f402534c21b2de7de3ffa777d51e033ed08d1db6aceeb488a4d4598243c0e01e43cb4f4492216ac3979e",
                "74ec06a96c017463d3cbff306f45386b9b1c082592ee923206c3847dde7f11ff417cd9172a18c2040c877bbc58b5e057667f8136bdd39038addc1f0e8eabe3f0" };

        for (int i = 0; i < dataVector.length; i++) {
            try {
                Hmac hmac = new Hmac();
                byte[] key = Util.h2b(keyVector[i]);
                byte[] data = Util.h2b(dataVector[i]);
                byte[] expected = Util.h2b(hashVector[i]);

                hmac.setKey(Hmac.SHA512, key);
                hmac.update(data);

                assertArrayEquals(expected, hmac.doFinal());

                hmac.reset();

                hmac.update(data);

                assertArrayEquals(expected, hmac.doFinal());

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA512 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    static final String[] sha3KeyVector = new String[] {
            "4A656665", /* Jefe  */
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0102030405060708010203040506070801020304050607080102030405060708" +
            "0102030405060708010203040506070801020304050607080102030405060708" +
            "0102030405060708010203040506070801020304050607080102030405060708" +
            "0102030405060708010203040506070801020304050607080102030405060708" +
            "0102030405060708010203040506070801020304050607080102030405060708"
    };
    static final String[] sha3DataVector = new String[] {
            /* what do ya want for nothing? */
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            /* Hi There */
            "4869205468657265",
            "dddddddddddddddddddd" +
            "dddddddddddddddddddd" +
            "dddddddddddddddddddd" +
            "dddddddddddddddddddd" +
            "dddddddddddddddddddd",
            /* Big Key Input */
            "426967204b657920496e707574"
    };

    @Test
    public void sha3_224HmacShouldMatch() {
        String[] hashVector = new String[] {
            "7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66",
            "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7",
            "676cfc7d16153638780390692be142d2df7ce924b909c0c08dbfdc1a",
            "29e05e46c4a45e4674bfd72d1ad866db2d0d104e2bfaad537d15698b"
        };

        for (int i = 0; i < sha3DataVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            try {
                Hmac hmac = new Hmac();

                byte[] key = Util.h2b(sha3KeyVector[i]);
                byte[] data = Util.h2b(sha3DataVector[i]);
                byte[] expected = Util.h2b(hashVector[i]);

                hmac.setKey(Hmac.SHA3_224, key);
                hmac.update(data);

                assertArrayEquals(expected, hmac.doFinal());

                hmac.reset();
                assertArrayEquals(expected, hmac.doFinal(data));

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA3-224 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void sha3_256HmacShouldMatch() {
        String[] hashVector = new String[] {
            "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5",
            "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
            "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207",
            "b55b8d64b69c21d0bf205ca2f7b9b14e8821612c66c391ae6c95168583e6f49b"
        };

        for (int i = 0; i < sha3DataVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            try {
                Hmac hmac = new Hmac();

                byte[] key = Util.h2b(sha3KeyVector[i]);
                byte[] expected = Util.h2b(hashVector[i]);
                byte[] data = Util.h2b(sha3DataVector[i]);

                hmac.setKey(Hmac.SHA3_256, key);
                hmac.update(data);

                assertArrayEquals(expected, hmac.doFinal());

                hmac.reset();
                assertArrayEquals(expected, hmac.doFinal(data));

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA3-256 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void sha3_384HmacShouldMatch() {
        String[] hashVector = new String[] {
            "f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a",
            "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd",
            "275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373b41b6ab5bf174bec422e53fc3135ac6e",
            "aa91b3a62f56a1be8c3e7438db58d9d334dea0606d8d46e0eca9f6063514e6ed83e67c77246c11b59082b575da7b832d"
        };

        for (int i = 0; i < sha3DataVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            try {
                Hmac hmac = new Hmac();

                byte[] key = Util.h2b(sha3KeyVector[i]);
                byte[] data = Util.h2b(sha3DataVector[i]);
                byte[] expected = Util.h2b(hashVector[i]);

                hmac.setKey(Hmac.SHA3_384, key);
                hmac.update(data);

                assertArrayEquals(expected, hmac.doFinal());

                hmac.reset();
                assertArrayEquals(expected, hmac.doFinal(data));

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA3-384 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void sha3_512HmacShouldMatch() {
        String[] hashVector = new String[] {
            "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024",
            "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e",
            "309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03",
            "1cc3a9244a4a3fbdc72000169b79470378752cb5f12e627cbeef4e8f0b112b32a0eec9d04d64640b37f4dd66f78bb3ad52526b6512de0d7cc08b60016c37d7a8"
        };

        for (int i = 0; i < sha3DataVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            try {
                Hmac hmac = new Hmac();

                byte[] expected = Util.h2b(hashVector[i]);
                byte[] data = Util.h2b(sha3DataVector[i]);

                hmac.setKey(Hmac.SHA3_512, Util.h2b(sha3KeyVector[i]));
                hmac.update(data);

                assertArrayEquals(expected, hmac.doFinal());

                hmac.reset();
                assertArrayEquals(expected, hmac.doFinal(data));

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("Hmac SHA3-512 test skipped: " +
                                       e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    private void threadRunnerHmacTest(int hmacType, byte[] inKey,
        byte[] inData, byte[] inExpected)
        throws InterruptedException {

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
        final int type = hmacType;
        final byte[] key = inKey;
        final byte[] data = inData;
        final byte[] expected = inExpected;

        /* Do HMAC across numThread threads, all should be successful */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int failed = 0;
                    Hmac hmac = null;

                    try {

                        hmac = new Hmac();
                        hmac.setKey(type, key);
                        hmac.update(data);

                        if (!Arrays.equals(expected, hmac.doFinal())) {
                            failed = 1;
                        }

                        if (failed == 0) {
                            hmac.reset();
                            hmac.update(data);
                            if (!Arrays.equals(expected, hmac.doFinal())) {
                                failed = 1;
                            }
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        failed = 1;

                    } finally {
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
                fail("Threading error in HMAC thread test");
            }
        }
    }

    @Test
    public void testThreadedHmac() throws InterruptedException {

        if (Hmac.SHA != -1) {
            threadRunnerHmacTest(Hmac.SHA,
                Util.h2b("fd42f5044e3f70825102017f8521"), /* key */
                Util.h2b("c9995cad63f60f7c7c552ac12c08" + /* data */
                         "0a7262cec4636d47c460c2abb47a" +
                         "f9bca09e18f9576c1415144595a7" +
                         "5da6fa232cb59d094d1a585c0710" +
                         "4856febcd05a58bde12a1f04795a" +
                         "e6e66a05b06f5dbe0dfa16c986fe" +
                         "fa8c3b2bce40cbb6c1ec74f1ad94" +
                         "7c1e9aadcf8584d5e9c45ec1f667" +
                         "567738b85bbdaad8dcd1e30fd35a" +
                         "3c61"),
                Util.h2b("8865eb9df41dcc2e74360f0c97ae" + /* expected */
                         "567cb2377022")
            );
        }
        if (Hmac.SHA256 != -1) {
            threadRunnerHmacTest(Hmac.SHA256,
                Util.h2b("26afdd2445b1f3cecbd4a797fed8"), /* key */
                Util.h2b("bd74f8646cdd9b217927b04ef4ee" + /* data */
                         "ef0b8ef0b78fafcabb11c202f8e8" +
                         "d44aeaf15d03ff315d014cbbab8e" +
                         "7ed48ab114567eb0cc525ed35bf9" +
                         "a96b61bd1d139cb386365c3cd5d1" +
                         "37e4717afd8ad2a2efc24b172b77" +
                         "27cc6bd5f8ddef652cceb87ae114" +
                         "f7cdfbd6c56473f414b8f149e616" +
                         "9e2dbd46333e526b5761892a2703" +
                         "a50e"),
                Util.h2b("208661dd6bdeab1c2843dfb8226c" + /* expected */
                         "be0a69db31aa183004e12025039f" +
                         "9fc2446a")
            );
        }
        if (Hmac.SHA384 != -1) {
            threadRunnerHmacTest(Hmac.SHA384,
                Util.h2b("d35d6a733af2947fbdb4a67f5b3d"), /* key */
                Util.h2b("44a8e36ec9b42a94a9627bd391f7" + /* data */
                         "114dad4296d31c3639a8a1d80188" +
                         "9b5c61e9378a0c81e4670a080712" +
                         "0c3ff0ecfd310dfbd9b95e91c244" +
                         "292851d8ef912a569e4ed3fc083c" +
                         "c62d9475c47534746dc8977a0e0a" +
                         "9f31bad5158f9c769cfe8b38e3ba" +
                         "dfe61f7a838bb9524c7c43d88998" +
                         "b186dccfc65f48e1ccd58a6888eb" +
                         "ad19"),
                Util.h2b("346ff5f9b77866d72154b6b6965f" + /* expected */
                         "1f56e7c21ddf3392bdbe12e5dffb" +
                         "1d75e2f0d919c1e133c83b9b56d3" +
                         "17c3db1364de")
            );
        }
        if (Hmac.SHA512 != -1) {
            threadRunnerHmacTest(Hmac.SHA512,
                Util.h2b("c3ec1135bb477eb81ca421deb9e0"), /* key */
                Util.h2b("837dbbb0371bf60082c788c8f16f" + /* data */
                         "f883dd9216d235f7decf7ea09f9e" +
                         "17fa5d46c25673bf609c7c4dfc3e" +
                         "740c0b6c1bcbf2879a1dc9d769ae" +
                         "5f8070d47eb26d66702195d1c1b5" +
                         "7e6847823cfc60facbad7b61adff" +
                         "da82d33196a1c1cae3b0ee7495c6" +
                         "690de3ccc2fc6b7a28c17782cfd0" +
                         "7f0a95a0ef60e4ff29e9daa8ce5b" +
                         "a717"),
                Util.h2b("517bd0146fe52cb464a0d555a7c2" + /* expected */
                         "9b5f9a604b07f32ff255f139156e" +
                         "214b6eb3836aa089987a5aca585e" +
                         "3cb10af8cb19c12a89628e8f59b6" +
                         "952ac4b7da7131f0")
            );
        }

        if (Hmac.SHA3_224 != -1) {
            threadRunnerHmacTest(Hmac.SHA3_224,
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), /* key */
                Util.h2b("4869205468657265"), /* data */
                Util.h2b("3b16546bbc7be2706a031dcafd56373d" +
                         "9884367641d8c59af3c860f7")
            );
        }
        if (Hmac.SHA3_256 != -1) {
            threadRunnerHmacTest(Hmac.SHA3_256,
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), /* key */
                Util.h2b("4869205468657265"), /* data */
                Util.h2b("ba85192310dffa96e2a3a40e697743" +
                         "51140bb7185e1202cdcc917589f95e" +
                         "16bb")
            );
        }
        if (Hmac.SHA3_384 != -1) {
            threadRunnerHmacTest(Hmac.SHA3_384,
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), /* key */
                Util.h2b("4869205468657265"), /* data */
                Util.h2b("68d2dcf7fd4ddd0a2240c8a437305f61" +
                         "fb7334cfb5d0226e1bc27dc10a2e723a" +
                         "20d370b47743130e26ac7e3d532886bd")
            );
        }
        if (Hmac.SHA3_512 != -1) {
            threadRunnerHmacTest(Hmac.SHA3_512,
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), /* key */
                Util.h2b("4869205468657265"), /* data */
                Util.h2b("eb3fbd4b2eaab8f5c504bd3a41465aac" +
                         "ec15770a7cabac531e482f860b5ec7ba" +
                         "47ccb2c6f2afce8f88d22b6dc61380f2" +
                         "3a668fd3888bb80537c0a0b86407689e")
            );
        }
    }
}
