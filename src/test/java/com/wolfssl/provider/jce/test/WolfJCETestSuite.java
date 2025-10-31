/* WolfJCETestSuite.java
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

package com.wolfssl.provider.jce.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({
    WolfCryptMessageDigestMd5Test.class,
    WolfCryptMessageDigestShaTest.class,
    WolfCryptMessageDigestSha224Test.class,
    WolfCryptMessageDigestSha256Test.class,
    WolfCryptMessageDigestSha384Test.class,
    WolfCryptMessageDigestSha512Test.class,
    WolfCryptMessageDigestSha3Test.class,
    WolfCryptRandomTest.class,
    WolfCryptSecretKeyTest.class,
    WolfCryptSecretKeyFactoryTest.class,
    WolfCryptSignatureTest.class,
    WolfCryptSignatureP1363Test.class,
    WolfCryptMacTest.class,
    WolfCryptCipherTest.class,
    WolfCryptKeyAgreementTest.class,
    WolfCryptKeyGeneratorTest.class,
    WolfCryptKeyPairGeneratorTest.class,
    WolfCryptECKeyFactoryTest.class,
    WolfCryptDHKeyFactoryTest.class,
    WolfCryptPKIXCertPathValidatorTest.class,
    WolfCryptAlgorithmParametersTest.class,
    WolfCryptAlgorithmParameterGeneratorTest.class,
    WolfCryptASN1UtilTest.class,
    WolfSSLKeyStoreTest.class,
    WolfCryptUtilTest.class
})

public class WolfJCETestSuite { }

