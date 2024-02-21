/* WolfSSLCertManager.java
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

package com.wolfssl.wolfcrypt;

import java.util.Enumeration;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;

/**
 * CertManager class which wraps the native wolfSSL functionality.
 * This class contains library init and cleanup methods, general callback
 * methods, as well as error codes and general wolfSSL codes.
 *
 * This class is very similar to the following wolfJSSE class:
 * wolfssljni/src/java/com/wolfssl/WolfSSLCertManager.java
 * We currently can't reuse that code since users are not guaranteed to have
 * both wolfcryptjni (wolfJCE) and wolfssljni (wolfJSSE) available and
 * installed. If we at some point end up merging wolfssljni and wolfcryptjni
 * together, one of the implementations can be removed and wolfJCE/JSSE
 * refactored to use a single implementation.
 *
 * @author  wolfSSL
 */
public class WolfSSLCertManager {
    private boolean active = false;
    private long cmPtr = 0;

    /* lock around active state */
    private final Object stateLock = new Object();

    /* lock around native WOLFSSL_CERT_MANAGER pointer use */
    private final Object cmLock = new Object();

    static native long CertManagerNew();
    static native void CertManagerFree(long cm);
    static native int CertManagerLoadCA(long cm, String f, String d);
    static native int CertManagerLoadCABuffer(
        long cm, byte[] in, long sz, int format);
    static native int CertManagerUnloadCAs(long cm);
    static native int CertManagerVerifyBuffer(
        long cm, byte[] in, long sz, int format);
    static native int CertManagerEnableCRL(long cm, int options);
    static native int CertManagerDisableCRL(long cm);
    static native int CertManagerLoadCRLBuffer(
        long cm, byte[] in, long sz, int type);

    /**
     * Create new WolfSSLCertManager object
     *
     * @throws WolfCryptException if unable to create new manager
     */
    public WolfSSLCertManager() throws WolfCryptException {
        cmPtr = CertManagerNew();
        if (cmPtr == 0) {
            throw new WolfCryptException("Failed to create WolfSSLCertManager");
        }
        this.active = true;
    }

    /**
     * Verifies that the current WolfSSLCertManager object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private synchronized void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLCertManager object has been freed");
            }
        }
    }

    /**
     * Load CA into CertManager
     *
     * @param f X.509 certificate file to load
     * @param d directory of X.509 certs to load, or null
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerLoadCA(String f, String d)
        throws IllegalStateException, WolfCryptException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (cmLock) {
            ret = CertManagerLoadCA(this.cmPtr, f, d);
            if (ret != WolfCrypt.WOLFSSL_SUCCESS) {
                throw new WolfCryptException(ret);
            }
        }
    }

    /**
     * Load CA into CertManager from byte array
     *
     * @param in byte array holding X.509 certificate to load
     * @param sz size of input byte array, bytes
     * @param format format of input certificate, either
     *               WolfCrypt.SSL_FILETYPE_PEM (PEM formatted) or
     *               WolfCrypt.SSL_FILETYPE_ASN1 (ASN.1/DER).
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerLoadCABuffer(
        byte[] in, long sz, int format)
        throws IllegalStateException, WolfCryptException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (cmLock) {
            ret = CertManagerLoadCABuffer(this.cmPtr, in, sz, format);
            if (ret != WolfCrypt.WOLFSSL_SUCCESS) {
                throw new WolfCryptException(ret);
            }
        }
    }

    /**
     * Load CA into CertManager from X509Certificate object.
     *
     * @param cert X509Certificate containing CA cert
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerLoadCA(X509Certificate cert)
        throws IllegalStateException, WolfCryptException {

        confirmObjectIsActive();

        if (cert == null) {
            throw new WolfCryptException("Input X509Certificate is null");
        }

        synchronized (cmLock) {
            try {
                /* Throws WolfCryptException on native error */
                CertManagerLoadCABuffer(cert.getEncoded(),
                    cert.getEncoded().length, WolfCrypt.SSL_FILETYPE_ASN1);
            } catch (CertificateEncodingException e) {
                throw new WolfCryptException(e);
            }
        }
    }

    /**
     * Loads KeyStore certificates into WolfSSLCertManager object.
     *
     * @param  ks - input KeyStore from which to load CA certs
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error or with error
     *         working with KeyStore
     */
    public synchronized void CertManagerLoadCAKeyStore(KeyStore ks)
        throws IllegalStateException, WolfCryptException {

        int ret = 0;
        int loadedCerts = 0;

        confirmObjectIsActive();

        if (ks == null) {
            throw new WolfCryptException("Input KeyStore is null");
        }

        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                X509Certificate cert = null;

                if (ks.isKeyEntry(name)) {
                    Certificate[] chain = ks.getCertificateChain(name);
                    if (chain != null) {
                        cert = (X509Certificate) chain[0];
                    }
                } else {
                    cert = (X509Certificate) ks.getCertificate(name);
                }

                if (cert != null && cert.getBasicConstraints() >= 0) {
                    /* Will throw WolfCryptException on error */
                    CertManagerLoadCABuffer(cert.getEncoded(),
                        cert.getEncoded().length,
                        WolfCrypt.SSL_FILETYPE_ASN1);
                    loadedCerts++;
                }
            }
        } catch (KeyStoreException | CertificateEncodingException ex) {
            throw new WolfCryptException(ex);
        }

        if (loadedCerts == 0) {
            throw new WolfCryptException(
                "Failed to load any CA certs from KeyStore");
        }
    }

    /**
     * Unload any CAs that have been loaded into WolfSSLCertManager object.
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerUnloadCAs()
        throws IllegalStateException, WolfCryptException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (cmLock) {
            ret = CertManagerUnloadCAs(this.cmPtr);
            if (ret != WolfCrypt.WOLFSSL_SUCCESS) {
                throw new WolfCryptException(ret);
            }
        }
    }

    /**
     * Verify X.509 certificate held in byte array. If verification fails
     * a WolfCryptException will be thrown, otherwise no exception if
     * verification passes.
     *
     * @param in input X.509 certificate as byte array
     * @param sz size of input certificate array, bytes
     * @param format format of input certificate, either
     *               WolfCrypt.SSL_FILETYPE_PEM (PEM formatted) or
     *               WolfCrypt.SSL_FILETYPE_ASN1 (ASN.1/DER).
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error or verification
     *         failure
     */
    public synchronized void CertManagerVerifyBuffer(
        byte[] in, long sz, int format)
        throws IllegalStateException, WolfCryptException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (cmLock) {
            ret = CertManagerVerifyBuffer(this.cmPtr, in, sz, format);
            if (ret != WolfCrypt.WOLFSSL_SUCCESS) {
                throw new WolfCryptException(ret);
            }
        }
    }

    /**
     * Verify X.509 certificate from X509Certificate object. If verification
     * fails a WolfCryptException will be thrown, otherwise no exception if
     * verification passes.
     *
     * @param cert X509Certificate to verify
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerVerify(
        X509Certificate cert)
        throws IllegalStateException, WolfCryptException {

        confirmObjectIsActive();

        if (cert == null) {
            throw new WolfCryptException("Input X509Certificate is null");
        }

        synchronized (cmLock) {
            try {
                /* Throws WolfCryptException on native error */
                CertManagerVerifyBuffer(cert.getEncoded(),
                    cert.getEncoded().length, WolfCrypt.SSL_FILETYPE_ASN1);
            } catch (CertificateEncodingException e) {
                throw new WolfCryptException(e);
            }
        }
    }

    /**
     * Enable CRL support in this WolfSSLCertManager when validating
     * certificates.
     *
     * @param options options for using CRLs. VAlid flags:
     *                    WolfSSLCertManager.WOLFSSL_CRL_CHECKALL
     *                    WolfSSLCertManager.WOLFSSL_CRL_CHECK
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error or CRL feature
     *         is not compiled into native wolfSSL
     */
    public synchronized void CertManagerEnableCRL(int options)
        throws IllegalStateException, WolfCryptException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (cmLock) {
            ret = CertManagerEnableCRL(this.cmPtr, options);
            if (ret != WolfCrypt.WOLFSSL_SUCCESS) {
                throw new WolfCryptException(ret);
            }
        }
    }

    /**
     * Disable CRL support in this WolfSSLCertManager.
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerDisableCRL()
        throws IllegalStateException, WolfCryptException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (cmLock) {
            ret = CertManagerDisableCRL(this.cmPtr);
            if (ret != WolfCrypt.WOLFSSL_SUCCESS) {
                throw new WolfCryptException(ret);
            }
        }
    }

    /**
     * Load CRL into CertManager from byte array
     *
     * @param in byte array holding CRL to load
     * @param sz size of input byte array, bytes
     * @param type format of input CRL, either
     *             WolfCrypt.SSL_FILETYPE_PEM (PEM formatted) or
     *             WolfCrypt.SSL_FILETYPE_ASN1 (ASN.1/DER).
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerLoadCRLBuffer(
        byte[] in, long sz, int type)
        throws IllegalStateException, WolfCryptException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (cmLock) {
            ret = CertManagerLoadCRLBuffer(this.cmPtr, in, sz, type);
            if (ret != WolfCrypt.WOLFSSL_SUCCESS) {
                throw new WolfCryptException(ret);
            }
        }
    }

    /**
     * Load CRL into WolfSSLCertManager from X509CRL object.
     *
     * @param crl X509CRL object to load as CRL into this WolfSSLCertManager
     *
     * @throws IllegalStateException WolfSSLCertManager has been freed
     * @throws WolfCryptException on native wolfSSL error
     */
    public synchronized void CertManagerLoadCRL(X509CRL crl)
        throws IllegalStateException, WolfCryptException {

        if (crl == null) {
            throw new WolfCryptException("Input X509CRL is null");
        }

        try {
            CertManagerLoadCRLBuffer(crl.getEncoded(),
                crl.getEncoded().length, WolfCrypt.SSL_FILETYPE_ASN1);
        } catch (CRLException e) {
            throw new WolfCryptException(e);
        }
    }

    /**
     * Free WolfSSLCertManager object
     */
    public synchronized void free() throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            synchronized (cmLock) {
                /* free native resources */
                CertManagerFree(this.cmPtr);

                /* free Java resources */
                this.active = false;
                this.cmPtr = 0;
            }
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public void finalize() throws Throwable
    {
        try {
            /* checks active state in this.free() */
            this.free();
        } catch (IllegalStateException e) {
            /* already freed */
        }
        super.finalize();
    }
}

