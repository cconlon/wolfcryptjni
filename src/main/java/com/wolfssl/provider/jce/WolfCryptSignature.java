/* WolfCryptSignature.java
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

package com.wolfssl.provider.jce;

import java.security.SignatureSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Asn;
import com.wolfssl.wolfcrypt.Md5;
import com.wolfssl.wolfcrypt.Sha;
import com.wolfssl.wolfcrypt.Sha224;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE Signature wrapper
 */
public class WolfCryptSignature extends SignatureSpi {

    enum KeyType {
        WC_RSA,
        WC_ECDSA
    }

    enum DigestType {
        WC_MD5,
        WC_SHA1,
        WC_SHA224,
        WC_SHA256,
        WC_SHA384,
        WC_SHA512
    }

    /* internal hash type sums (asn.h) */
    private int MD5h = 649;
    private int SHAh = 88;
    private int SHA224h = 417;
    private int SHA256h = 414;
    private int SHA384h = 415;
    private int SHA512h = 416;

    /* internal key objects */
    private Rsa rsa = null;
    private Ecc ecc = null;

    /* internal hash objects */
    private Md5 md5 = null;
    private Sha sha = null;
    private Sha224 sha224 = null;
    private Sha256 sha256 = null;
    private Sha384 sha384 = null;
    private Sha512 sha512 = null;

    private KeyType keyType;        /* active key type, from KeyType */
    private DigestType digestType;  /* active digest type, from DigestType */
    private int internalHashSum;    /* used for native EncodeSignature */
    private int digestSz;           /* digest size in bytes */

    /* for debug logging */
    private String keyString;
    private String digestString;

    /* Class-wide RNG to be used for padding during sign operations */
    private Rng rng = null;
    private final Object rngLock = new Object();

    private WolfCryptSignature(KeyType ktype, DigestType dtype)
        throws NoSuchAlgorithmException {

        this.keyType = ktype;
        this.digestType = dtype;

        if ((ktype != KeyType.WC_RSA) &&
            (ktype != KeyType.WC_ECDSA)) {
            throw new NoSuchAlgorithmException(
                "Signature algorithm key type must be RSA or ECC");
        }

        synchronized (rngLock) {
            this.rng = new Rng();
            this.rng.init();
        }

        /* init hash type */
        switch (dtype) {
            case WC_MD5:
                this.md5 = new Md5();
                this.digestSz = Md5.DIGEST_SIZE;
                this.internalHashSum = MD5h;
                break;

            case WC_SHA1:
                this.sha = new Sha();
                this.digestSz = Sha.DIGEST_SIZE;
                this.internalHashSum = SHAh;
                break;

            case WC_SHA224:
                this.sha224 = new Sha224();
                this.digestSz = Sha224.DIGEST_SIZE;
                this.internalHashSum = SHA224h;
                break;

            case WC_SHA256:
                this.sha256 = new Sha256();
                this.digestSz = Sha256.DIGEST_SIZE;
                this.internalHashSum = SHA256h;
                break;

            case WC_SHA384:
                this.sha384 = new Sha384();
                this.digestSz = Sha384.DIGEST_SIZE;
                this.internalHashSum = SHA384h;
                break;

            case WC_SHA512:
                this.sha512 = new Sha512();
                this.digestSz = Sha512.DIGEST_SIZE;
                this.internalHashSum = SHA512h;
                break;

            default:
                throw new NoSuchAlgorithmException(
                    "Unsupported signature algorithm digest type");
        }

        if (WolfCryptDebug.DEBUG) {
            keyString = typeToString(ktype);
            digestString = digestToString(dtype);
        }
    }

    @Deprecated
    @Override
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "wolfJCE does not support Signature.getParameter()");
    }

    private void wolfCryptInitPrivateKey(PrivateKey key, byte[] encodedKey)
        throws InvalidKeyException {

        switch (this.keyType) {

            case WC_RSA:

                /* import private PKCS#8 */
                this.rsa.decodePrivateKeyPKCS8(encodedKey);

                break;

            case WC_ECDSA:

                ECPrivateKey ecPriv = (ECPrivateKey)key;
                this.ecc.importPrivate(ecPriv.getS().toByteArray(), null);

                break;
        }
    }

    private void wolfCryptInitPublicKey(PublicKey key, byte[] encodedKey)
        throws InvalidKeyException {

        switch(this.keyType) {

            case WC_RSA:

                this.rsa.decodePublicKey(encodedKey);

                break;

            case WC_ECDSA:

                this.ecc.publicKeyDecode(encodedKey);

                break;
        }
    }

    @Override
    protected synchronized void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException {

        byte[] encodedKey;

        if (this.keyType == KeyType.WC_RSA &&
                !(privateKey instanceof RSAPrivateKey)) {
            throw new InvalidKeyException("Key is not of type RSAPrivateKey");

        } else if (this.keyType == KeyType.WC_ECDSA &&
                !(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Key is not of type ECPrivateKey");
        }

        /* get encoded key, returns PKCS#8 formatted private key */
        encodedKey = privateKey.getEncoded();
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        /* initialize native struct */
        switch (keyType) {
            case WC_RSA:
                if (this.rsa != null) {
                    this.rsa.releaseNativeStruct();
                }
                this.rsa = new Rsa();
                break;
            case WC_ECDSA:
                if (this.ecc != null) {
                    this.ecc.releaseNativeStruct();
                }
                synchronized (this.rngLock) {
                    this.ecc = new Ecc(this.rng);
                }
                break;
        }

        wolfCryptInitPrivateKey(privateKey, encodedKey);

        /* init hash object */
        switch (this.digestType) {
            case WC_MD5:
                this.md5.init();
                break;

            case WC_SHA1:
                this.sha.init();
                break;

            case WC_SHA224:
                this.sha224.init();
                break;

            case WC_SHA256:
                this.sha256.init();
                break;

            case WC_SHA384:
                this.sha384.init();
                break;

            case WC_SHA512:
                this.sha512.init();
                break;
        }

        log("init sign with PrivateKey");
    }

    @Override
    protected synchronized void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException {

        byte[] encodedKey;

        if (this.keyType == KeyType.WC_RSA &&
                !(publicKey instanceof RSAPublicKey)) {
            throw new InvalidKeyException("Key is not of type RSAPublicKey");

        } else if (this.keyType == KeyType.WC_ECDSA &&
                !(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("Key is not of type ECPublicKey");
        }

        /* get encoded key, returns PKCS#8 formatted private key */
        encodedKey = publicKey.getEncoded();
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        /* initialize native struct */
        switch (keyType) {
            case WC_RSA:
                if (this.rsa != null) {
                    this.rsa.releaseNativeStruct();
                }
                this.rsa = new Rsa();
                break;
            case WC_ECDSA:
                if (this.ecc != null) {
                    this.ecc.releaseNativeStruct();
                }
                synchronized (this.rngLock) {
                    this.ecc = new Ecc(this.rng);
                }
                break;
        }

        wolfCryptInitPublicKey(publicKey, encodedKey);

        /* init hash object */
        switch (this.digestType) {
            case WC_MD5:
                this.md5.init();
                break;

            case WC_SHA1:
                this.sha.init();
                break;

            case WC_SHA224:
                this.sha224.init();
                break;

            case WC_SHA256:
                this.sha256.init();
                break;

            case WC_SHA384:
                this.sha384.init();
                break;

            case WC_SHA512:
                this.sha512.init();
                break;
        }

        log("init verify with PublicKey");
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "wolfJCE does not support Signature.setParameter()");
    }

    @Override
    protected synchronized byte[] engineSign() throws SignatureException {

        int encodedSz = 0;

        byte[] digest    = new byte[this.digestSz];
        byte[] encDigest = new byte[Asn.MAX_ENCODED_SIG_SIZE];
        byte[] signature = new byte[Asn.MAX_ENCODED_SIG_SIZE];

        /* get final digest */
        try {
            switch (this.digestType) {
                case WC_MD5:
                    this.md5.digest(digest);
                    break;

                case WC_SHA1:
                    this.sha.digest(digest);
                    break;

                case WC_SHA224:
                    this.sha224.digest(digest);
                    break;

                case WC_SHA256:
                    this.sha256.digest(digest);
                    break;

                case WC_SHA384:
                    this.sha384.digest(digest);
                    break;

                case WC_SHA512:
                    this.sha512.digest(digest);
                    break;
            }

        } catch (ShortBufferException e) {
            throw new SignatureException(e.getMessage());
        }

        /* sign digest */
        switch (this.keyType) {
            case WC_RSA:

                /* DER encode digest */
                encodedSz = (int)Asn.encodeSignature(encDigest, digest,
                                digest.length, this.internalHashSum);

                if (encodedSz < 0) {
                    throw new SignatureException(
                        "Failed to DER encode digest during sig gen");
                }

                byte[] tmp = new byte[encodedSz];
                System.arraycopy(encDigest, 0, tmp, 0, encodedSz);
                synchronized (rngLock) {
                    signature = this.rsa.sign(tmp, this.rng);
                }
                zeroArray(tmp);

                break;

            case WC_ECDSA:

                /* ECC sign */
                synchronized (rngLock) {
                    signature = this.ecc.sign(digest, this.rng);
                }

                break;

            default:
                throw new SignatureException(
                    "Invalid signature algorithm type");
        }

        if (signature != null) {
            log("generated signature, len: " + signature.length);
        } else {
            log("generated signature was null");
        }

        return signature;
    }

    @Override
    protected synchronized void engineUpdate(byte b) throws SignatureException {

        byte[] tmp = new byte[1];
        tmp[0] = b;

        engineUpdate(tmp, 0, 1);

        log("update with single byte");
    }

    @Override
    protected synchronized void engineUpdate(byte[] b, int off, int len)
        throws SignatureException {

        switch (this.digestType) {
            case WC_MD5:
                this.md5.update(b, off, len);
                break;

            case WC_SHA1:
                this.sha.update(b, off, len);
                break;

            case WC_SHA224:
                this.sha224.update(b, off, len);
                break;

            case WC_SHA256:
                this.sha256.update(b, off, len);
                break;

            case WC_SHA384:
                this.sha384.update(b, off, len);
                break;

            case WC_SHA512:
                this.sha512.update(b, off, len);
                break;
        }

        log("update, offset: " + off + ", len: " + len);
    }

    @Override
    protected synchronized boolean engineVerify(byte[] sigBytes)
        throws SignatureException {

        long   encodedSz = 0;
        boolean verified = true;

        byte[] digest    = new byte[this.digestSz];
        byte[] encDigest = new byte[Asn.MAX_ENCODED_SIG_SIZE];
        byte[] verify    = new byte[Asn.MAX_ENCODED_SIG_SIZE];

        /* get final digest */
        try {
            switch (this.digestType) {
                case WC_MD5:
                    this.md5.digest(digest);
                    break;

                case WC_SHA1:
                    this.sha.digest(digest);
                    break;

                case WC_SHA224:
                    this.sha224.digest(digest);
                    break;

                case WC_SHA256:
                    this.sha256.digest(digest);
                    break;

                case WC_SHA384:
                    this.sha384.digest(digest);
                    break;

                case WC_SHA512:
                    this.sha512.digest(digest);
                    break;
            }

        } catch (ShortBufferException e) {
            throw new SignatureException(e.getMessage());
        }

        /* verify digest */
        switch (this.keyType) {
            case WC_RSA:

                /* DER encode digest */
                encodedSz = Asn.encodeSignature(encDigest, digest,
                                digest.length, this.internalHashSum);

                if (encodedSz < 0) {
                    throw new SignatureException(
                        "Failed to DER encode digest during sig verification");
                }

                try {
                    verify = this.rsa.verify(sigBytes);
                } catch (WolfCryptException e) {
                    verified = false;
                }

                /* compare expected digest to one unwrapped from verify */
                for (int i = 0; i < verify.length; i++) {
                    if (verify[i] != encDigest[i]) {
                        verified = false;
                    }
                }

                break;

            case WC_ECDSA:

                try {
                    verified = this.ecc.verify(digest, sigBytes);
                } catch (WolfCryptException we) {
                    verified = false;
                }

                break;
        }

        if (sigBytes != null) {
            log("finished verify of sig len: " + sigBytes.length +
                ", verified: " + verified);
        }

        return verified;
    }

    private void zeroArray(byte[] in) {

        if (in == null)
            return;

        for (int i = 0; i < in.length; i++) {
            in[i] = 0;
        }
    }

    private String typeToString(KeyType type) {
        switch (type) {
            case WC_RSA:
                return "RSA";
            case WC_ECDSA:
                return "ECDSA";
            default:
                return "None";
        }
    }

    private String digestToString(DigestType type) {
        switch (type) {
            case WC_MD5:
                return "MD5";
            case WC_SHA1:
                return "SHA";
            case WC_SHA224:
                return "SHA224";
            case WC_SHA256:
                return "SHA256";
            case WC_SHA384:
                return "SHA384";
            case WC_SHA512:
                return "SHA512";
            default:
                return "None";
        }
    }

    private void log(String msg) {
        WolfCryptDebug.print("[Signature, " + keyString + "-" +
            digestString + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            /* free native digest objects */
            if (this.md5 != null)
                this.md5.releaseNativeStruct();

            if (this.sha != null)
                this.sha.releaseNativeStruct();

            if (this.sha224 != null)
                this.sha224.releaseNativeStruct();

            if (this.sha256 != null)
                this.sha256.releaseNativeStruct();

            if (this.sha384 != null)
                this.sha384.releaseNativeStruct();

            if (this.sha512 != null)
                this.sha512.releaseNativeStruct();

            /* free native key objects */
            if (this.rsa != null)
                this.rsa.releaseNativeStruct();

            if (this.ecc != null)
                this.ecc.releaseNativeStruct();  /* frees internally */

            synchronized (rngLock) {
                if (this.rng != null) {
                    /* release RNG */
                    this.rng.free();
                    this.rng.releaseNativeStruct();
                    this.rng = null;
                }
            }

        } finally {
            super.finalize();
        }
    }

    /**
     * wolfJCE MD5wRSA signature class
     */
    public static final class wcMD5wRSA extends WolfCryptSignature {
        /**
         * Create new wcMD5wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcMD5wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_MD5);
        }
    }

    /**
     * wolfJCE SHA1wRSA signature class
     */
    public static final class wcSHA1wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA1wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA1wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA1);
        }
    }

    /**
     * wolfJCE SHA224wRSA signature class
     */
    public static final class wcSHA224wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA224wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA224wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA224);
        }
    }

    /**
     * wolfJCE SHA256wRSA signature class
     */
    public static final class wcSHA256wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA256wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA256wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA256);
        }
    }

    /**
     * wolfJCE SHA384wRSA signature class
     */
    public static final class wcSHA384wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA384wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA384wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA384);
        }
    }

    /**
     * wolfJCE SHA512wRSA signature class
     */
    public static final class wcSHA512wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA512wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA512wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA512);
        }
    }

    /**
     * wolfJCE SHA1wECDSA signature class
     */
    public static final class wcSHA1wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA1wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA1wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA1);
        }
    }

    /**
     * wolfJCE SHA224wECDSA signature class
     */
    public static final class wcSHA224wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA224wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA224wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA224);
        }
    }

    /**
     * wolfJCE SHA256wECDSA signature class
     */
    public static final class wcSHA256wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA256wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA256wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA256);
        }
    }

    /**
     * wolfJCE SHA384wECDSA signature class
     */
    public static final class wcSHA384wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA384wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA384wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA384);
        }
    }

    /**
     * wolfJCE SHA512wECDSA signature class
     */
    public static final class wcSHA512wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA512wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA512wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA512);
        }
    }
}

