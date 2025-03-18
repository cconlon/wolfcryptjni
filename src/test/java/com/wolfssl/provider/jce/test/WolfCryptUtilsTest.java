/* WolfCryptUtilsTest.java
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

import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.BeforeClass;
import org.junit.AfterClass;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.Provider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateFactory;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptUtils;

/**
 * Test suite for WolfCryptUtils.convertKeyStoreToWKS method.
 * 
 * Tests converting JKS KeyStore to WKS format and error handling.
 */
public class WolfCryptUtilsTest {
    
    /* Common test password for test KeyStores */
    private static final char[] PASSWORD = "wolfSSL test".toCharArray();
    private static final String WKS_TYPE = "WKS";
    private static final String WKS_PROVIDER = "wolfJCE";
    
    /* Original security property values */
    private static String origMapJksToWks = null;
    private static String origMapPkcs12ToWks = null;
    
    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };
    
    @BeforeClass
    public static void setUpClass() {

        System.out.println("JCE WolfCryptUtils Class");

        /* Register wolfJCE provider if not already done */
        Provider wolfJCE = Security.getProvider(WKS_PROVIDER);
        if (wolfJCE == null) {
            Security.insertProviderAt(new WolfCryptProvider(), 1);
        }
        
        /* Store original security property values */
        origMapJksToWks = Security.getProperty("wolfjce.mapJKStoWKS");
        origMapPkcs12ToWks = Security.getProperty("wolfjce.mapPKCS12toWKS");
        
        /* Make sure we set them to known values at the start */
        Security.setProperty("wolfjce.mapJKStoWKS", "false");
        Security.setProperty("wolfjce.mapPKCS12toWKS", "false");
    }
    
    @AfterClass
    public static void tearDownClass() {
        /* Restore original security property values */
        if (origMapJksToWks != null) {
            Security.setProperty("wolfjce.mapJKStoWKS", origMapJksToWks);
        } else {
            Security.setProperty("wolfjce.mapJKStoWKS", "false");
        }
        
        if (origMapPkcs12ToWks != null) {
            Security.setProperty("wolfjce.mapPKCS12toWKS", origMapPkcs12ToWks);
        } else {
            Security.setProperty("wolfjce.mapPKCS12toWKS", "false");
        }
    }
    
    /**
     * Test with null input stream (should throw an exception)
     */
    @Test
    public void testNullInputStream() {
        try {
            WolfCryptUtils.convertKeyStoreToWKS(null, PASSWORD);
            fail("Should have thrown an exception for null input stream");
        } catch (IllegalArgumentException e) {
            /* Expected exception */
            assertTrue("Exception message should indicate null input stream",
                e.getMessage().contains("null"));
        } catch (Exception e) {
            fail("Unexpected exception type: " + e.getClass().getName());
        }
    }
    
    /**
     * Test with null password (should throw an exception)
     */
    @Test
    public void testNullPassword() {
        /* Create a dummy keystore for testing */
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, PASSWORD);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, PASSWORD);
            ByteArrayInputStream bais =
                new ByteArrayInputStream(baos.toByteArray());
            
            WolfCryptUtils.convertKeyStoreToWKS(bais, null);
            fail("Should have thrown an exception for null password");
        } catch (IllegalArgumentException e) {
            /* Expected exception */
            assertTrue("Exception message should indicate null password",
                e.getMessage().contains("null"));
        } catch (Exception e) {
            fail("Unexpected exception type: " + e.getClass().getName());
        }
    }
}

