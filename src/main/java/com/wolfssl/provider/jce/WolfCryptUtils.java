/* WolfCryptUtils.java
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * Utility class containing helper functions for wolfCrypt JCE provider.
 */
public class WolfCryptUtils {

    /**
     * Converts a Java KeyStore (JKS or PKCS12) to a WolfSSLKeyStore (WKS) 
     * format.
     *
     * This method detects the type of the input KeyStore (JKS or PKCS12) and 
     * converts it to WKS format. All certificates and keys from the source 
     * KeyStore are transferred to the destination KeyStore.
     *
     * @param stream Input stream containing a JKS or PKCS12 KeyStore
     * @param password Password used to decrypt KeyStore entries
     * @return InputStream containing the newly created WKS KeyStore
     * @throws IOException If an I/O error occurs
     * @throws NoSuchProviderException If required security providers are not
     *         available or if reflection operations fail when accessing the
     *         original KeyStore implementations
     */
    public static InputStream convertKeyStoreToWKS(InputStream stream, 
            char[] password) throws IOException, NoSuchProviderException {
        
        if (stream == null) {
            throw new IllegalArgumentException("Input stream cannot be null");
        }
        
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        
        /* Make sure wolfJCE provider is available and registered */
        Provider wolfJCE = Security.getProvider("wolfJCE");
        if (wolfJCE == null) {
            wolfJCE = new WolfCryptProvider();
            Security.addProvider(wolfJCE);
        }
        
        try {
            /* Check if wolfJCE has mapped JKS or PKCS12 to WKS */
            boolean mapJKStoWKS = "true".equalsIgnoreCase(
                    Security.getProperty("wolfjce.mapJKStoWKS"));
            boolean mapPKCS12toWKS = "true".equalsIgnoreCase(
                    Security.getProperty("wolfjce.mapPKCS12toWKS"));
            
            /* Try to detect source KeyStore type (JKS or PKCS12) */
            KeyStore sourceStore = null;
            
            /* Make sure we can reset the stream if needed */
            if (!stream.markSupported()) {
                try {
                    /* Read all bytes from stream into a ByteArrayOutputStream */
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    int nRead;
                    byte[] data = new byte[4096];
                    while ((nRead = stream.read(data, 0, data.length)) != -1) {
                        buffer.write(data, 0, nRead);
                    }
                    buffer.flush();
                    byte[] byteArray = buffer.toByteArray();
                    stream = new ByteArrayInputStream(byteArray);
                } catch (IOException e) {
                    throw new IOException("Failed to read stream contents", e);
                }
            }
            
            /* Mark the stream to return to this position after detection 
             * attempts. Mark with enough buffer for large keystores */
            stream.mark(8192);
            
            try {
                /* Try JKS first */
                if (mapJKStoWKS) {
                    /* If JKS is mapped to WKS, use reflection to get the Sun 
                     * provider's JKS implementation */
                    try {
                        sourceStore = getJksKeyStoreFromSunProvider();
                    } catch (ReflectiveOperationException | KeyStoreException ex) {
                        throw new NoSuchProviderException(
                            "Failed to get JKS implementation via reflection: " + 
                            ex.getMessage());
                    }
                } else {
                    sourceStore = KeyStore.getInstance("JKS");
                }
                sourceStore.load(stream, password);
            } catch (IOException | NoSuchAlgorithmException | 
                       CertificateException e) {
                /* If JKS fails, reset the stream and try PKCS12 */
                stream.reset();
                
                try {
                    if (mapPKCS12toWKS) {
                        /* If PKCS12 is mapped to WKS, use reflection to get 
                         * the Sun provider's PKCS12 implementation */
                        try {
                            sourceStore = getPkcs12KeyStoreFromSunProvider();
                        } catch (ReflectiveOperationException | KeyStoreException ex) {
                            throw new NoSuchProviderException(
                                "Failed to get PKCS12 implementation via reflection: " + 
                                ex.getMessage());
                        }
                    } else {
                        sourceStore = KeyStore.getInstance("PKCS12");
                    }
                    sourceStore.load(stream, password);
                } catch (KeyStoreException | NoSuchAlgorithmException | 
                           CertificateException ex) {
                    throw new IOException(
                        "Input is neither JKS nor PKCS12 KeyStore format", ex);
                }
            }
            
            /* Create destination WKS KeyStore */
            KeyStore destStore = KeyStore.getInstance("WKS", "wolfJCE");
            destStore.load(null, password);
            
            /* Copy all entries from source to destination */
            Enumeration<String> aliases = sourceStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                if (sourceStore.isKeyEntry(alias)) {
                    /* Handle key entries (which may include a certificate 
                     * chain) */
                    Key key;
                    try {
                        key = sourceStore.getKey(alias, password);
                        Certificate[] chain = 
                            sourceStore.getCertificateChain(alias);
                        destStore.setKeyEntry(alias, key, password, chain);
                    } catch (UnrecoverableKeyException | KeyStoreException e) {
                        throw new IOException("Failed to copy key entry: " + 
                            alias, e);
                    }
                } else if (sourceStore.isCertificateEntry(alias)) {
                    /* Handle certificate-only entries */
                    try {
                        Certificate cert = sourceStore.getCertificate(alias);
                        destStore.setCertificateEntry(alias, cert);
                    } catch (KeyStoreException e) {
                        throw new IOException(
                            "Failed to copy certificate entry: " + alias, e);
                    }
                }
            }
            
            /* Write the WKS KeyStore to a byte array and return as 
             * InputStream */
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            destStore.store(baos, password);
            return new ByteArrayInputStream(baos.toByteArray());
            
        } catch (KeyStoreException | NoSuchAlgorithmException | 
                   CertificateException e) {
            throw new IOException("Error during KeyStore conversion", e);
        }
    }
    
    /**
     * Gets the Sun provider's JKS KeyStore implementation using reflection.
     * This is used when wolfJCE has registered itself as the JKS provider.
     *
     * @return A KeyStore instance from the Sun provider for JKS format
     * @throws ReflectiveOperationException If reflection fails
     * @throws KeyStoreException If the KeyStore cannot be created
     */
    private static KeyStore getJksKeyStoreFromSunProvider() 
            throws ReflectiveOperationException, KeyStoreException {
        /* Try to find the Sun provider */
        Provider sunProvider = Security.getProvider("SUN");
        if (sunProvider == null) {
            throw new KeyStoreException("SUN provider not available");
        }
        
        try {
            /* Load the JKS KeyStore class directly from the Sun provider */
            Class<?> jksKeyStoreClass = 
                Class.forName("sun.security.provider.JavaKeyStore$JKS");
            Constructor<?> constructor = 
                jksKeyStoreClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            KeyStore ks = (KeyStore) constructor.newInstance();
            
            /* Initialize the KeyStore */
            Method engineInitMethod = 
                jksKeyStoreClass.getDeclaredMethod("engineInit");
            engineInitMethod.setAccessible(true);
            engineInitMethod.invoke(ks);
            
            return ks;
        } catch (ClassNotFoundException e) {
            /* Fallback to another approach if the first one fails */
            /* Try to get the KeyStore through the provider */
            return KeyStore.getInstance("JKS", sunProvider);
        }
    }
    
    /**
     * Gets the Sun provider's PKCS12 KeyStore implementation using reflection.
     * This is used when wolfJCE has registered itself as the PKCS12 provider.
     *
     * @return A KeyStore instance from the Sun provider for PKCS12 format
     * @throws ReflectiveOperationException If reflection fails
     * @throws KeyStoreException If the KeyStore cannot be created
     */
    private static KeyStore getPkcs12KeyStoreFromSunProvider() 
            throws ReflectiveOperationException, KeyStoreException {
        /* Try to find the SunJSSE provider */
        Provider sunJsseProvider = Security.getProvider("SunJSSE");
        if (sunJsseProvider == null) {
            /* Try Sun provider as fallback */
            sunJsseProvider = Security.getProvider("SUN");
            if (sunJsseProvider == null) {
                throw new KeyStoreException(
                    "Neither SunJSSE nor SUN provider available");
            }
        }
        
        try {
            /* Load the PKCS12 KeyStore class */
            Class<?> pkcs12KeyStoreClass = 
                Class.forName("sun.security.pkcs12.PKCS12KeyStore");
            Constructor<?> constructor = 
                pkcs12KeyStoreClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            KeyStore ks = (KeyStore) constructor.newInstance();
            
            /* Initialize the KeyStore */
            Method engineInitMethod = 
                pkcs12KeyStoreClass.getDeclaredMethod("engineInit");
            engineInitMethod.setAccessible(true);
            engineInitMethod.invoke(ks);
            
            return ks;
        } catch (ClassNotFoundException e) {
            /* Fallback to another approach if the first one fails */
            /* Try to get the KeyStore through the provider */
            return KeyStore.getInstance("PKCS12", sunJsseProvider);
        }
    }
}

