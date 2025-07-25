/* MessageDigest.java
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;
import javax.crypto.ShortBufferException;

/**
 * Common API for Message Digests
 */
public abstract class MessageDigest extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Default MessageDigest constructor */
    public MessageDigest() { }

    /**
     * Initialize native structure
     */
    protected abstract void native_init();

    /**
     * Native update
     *
     * @param data input data
     * @param offset offset into input data
     * @param length length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_update(ByteBuffer data, int offset,
        int length);

    /**
     * Native update
     *
     * @param data input data
     * @param offset offset into input data
     * @param length length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_update(byte[] data, int offset, int length);

    /**
     * Native final - calculate final digest
     *
     * @param hash output buffer to place digest
     * @param offset offset into output buffer to write digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_final(ByteBuffer hash, int offset);

    /**
     * Native final - calculate final digest
     *
     * @param hash output buffer to place digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_final(byte[] hash);

    /**
     * Get digest size
     *
     * @return digest size
     */
    public abstract int digestSize();

    /**
     * Initialize object
     */
    public synchronized void init() {
        /* Allocate native struct pointer from NativeStruct */
        initNativeStruct();

        /* Initialize native struct and set READY state */
        native_init();
        state = WolfCryptState.READY;
    }

    /**
     * Internal helper method to initialize object if/when needed.
     *
     * @throws IllegalStateException on failure to initialize properly
     */
    protected synchronized void checkStateAndInitialize()
        throws IllegalStateException {

        if (state == WolfCryptState.UNINITIALIZED) {
            init();
        }

        if (state != WolfCryptState.READY) {
            throw new IllegalStateException("Failed to initialize Object");
        }
    }

    /**
     * Message digest update
     *
     * @param data input data
     * @param length length of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized void update(ByteBuffer data, int length)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        length = Math.min(length, data.remaining());

        native_update(data, data.position(), length);
        data.position(data.position() + length);
    }

    /**
     * Message digest update
     *
     * @param data input data, use all data.remaining()
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized void update(ByteBuffer data)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        update(data, data.remaining());
    }

    /**
     * Message digest update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized void update(byte[] data, int offset, int len)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        if (offset >= data.length || offset < 0 || len < 0)
            return;

        if (data.length - offset < len)
            len = data.length - offset;

        native_update(data, offset, len);
    }

    /**
     * Message digest update
     *
     * @param data input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized void update(byte[] data, int len)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        update(data, 0, len);
    }

    /**
     * Message digest update
     *
     * @param data input data, use all data.length
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized void update(byte[] data)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        update(data, 0, data.length);
    }

    /**
     * Calculate message digest
     *
     * @param hash output message digest
     *
     * @throws WolfCryptException if native operation fails
     * @throws ShortBufferException if input buffer is too small
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized void digest(ByteBuffer hash)
        throws ShortBufferException, WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        if (hash.remaining() < digestSize()) {
            throw new ShortBufferException(
                "Input buffer is too small for digest size");
        }

        native_final(hash, hash.position());
        hash.position(hash.position() + digestSize());

        /* After digest is finalized, reset state to allow re-initialization */
        state = WolfCryptState.UNINITIALIZED;
    }

    /**
     * Calculate message digest
     *
     * @param hash output message digest
     *
     * @throws WolfCryptException if native operation fails
     * @throws ShortBufferException if input buffer is too small
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized void digest(byte[] hash)
        throws ShortBufferException, WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        if (hash.length < digestSize()) {
            throw new ShortBufferException(
                "Input buffer is too small for digest size");
        }

        native_final(hash);

        /* After digest is finalized, reset state to allow re-initialization */
        state = WolfCryptState.UNINITIALIZED;
    }

    /**
     * Calculate message digest
     *
     * @return resulting message digest
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object fails to initialize properly
     */
    public synchronized byte[] digest()
        throws WolfCryptException, IllegalStateException {

        byte[] hash = new byte[digestSize()];

        checkStateAndInitialize();

        native_final(hash);

        /* After digest is finalized, reset state to allow re-initialization */
        state = WolfCryptState.UNINITIALIZED;

        return hash;
    }

    @Override
    public synchronized void releaseNativeStruct() {

        /* reset state first, then free */
        state = WolfCryptState.UNINITIALIZED;
        super.releaseNativeStruct();
    }
}

