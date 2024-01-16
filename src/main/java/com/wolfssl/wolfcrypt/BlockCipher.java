/* BlockCipher.java
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

import java.util.Arrays;
import java.nio.ByteBuffer;

import javax.crypto.ShortBufferException;

/**
 * Common API for block ciphers.
 */
public abstract class BlockCipher extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    private int opmode;

    /** Default BlockCipher constructor */
    public BlockCipher() { }

    /**
     * Set block cipher key, IV, and mode
     *
     * @param key block cipher key array
     * @param iv block cipher initialization vector (IV) array
     * @param opmode block cipher operation mode, dependent on subclass type
     */
    protected abstract void native_set_key(byte[] key, byte[] iv, int opmode);

    /**
     * Native block cipher encrypt/decrypt update operation
     *
     * @param opmode operation mode, depends on subclass type
     * @param input input data
     * @param offset offset into input array
     * @param length length of data in input to update
     * @param output output array
     * @param outputOffset offset into output array to write data
     *
     * @return number of bytes stored in output
     */
    protected abstract int native_update(int opmode, byte[] input, int offset,
            int length, byte[] output, int outputOffset);

    /**
     * Native block cipher encrypt/decrypt update operation
     *
     * @param opmode operation mode, depends on subclass type
     * @param input input data
     * @param offset offset into input array
     * @param length length of data in input to update
     * @param output output buffer
     * @param outputOffset offset into output buffer to write data
     *
     * @return number of bytes stored in output
     */
    protected abstract int native_update(int opmode, ByteBuffer input,
            int offset, int length, ByteBuffer output, int outputOffset);

    /**
     * Set block cipher key, IV, and mode
     *
     * @param key block cipher key array
     * @param iv block cipher initialization vector (IV) array
     * @param opmode block cipher operation mode, dependent on subclass type
     */
    public synchronized void setKey(byte[] key, byte[] iv, int opmode) {

        native_set_key(key, iv, opmode);

        this.opmode = opmode;
        state = WolfCryptState.READY;
    }

    /**
     * Throws IllegalStateException if key not usable
     *
     * @throws IllegalStateException if algorithm or key not usable
     */
    public synchronized void willUseKey() {

        if (state != WolfCryptState.READY)
            throw new IllegalStateException(
                    "No available key to perform the opperation.");
    }

    /**
     * Block cipher update operation
     *
     * @param input input data for update
     *
     * @return output data array from update operation
     */
    public synchronized byte[] update(byte[] input) {

        return update(input, 0, input.length);
    }

    /**
     * Block cipher update operation
     *
     * @param input input data for update
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     *
     * @return output data array from update operation
     */
    public synchronized byte[] update(byte[] input, int offset, int length) {

        willUseKey();

        byte[] output = new byte[input.length];

        native_update(opmode, input, offset, length, output, 0);

        return output;
    }

    /**
     * Block cipher update operation
     *
     * @param input input data for update
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     * @param output output array to place data
     * @param outputOffset offset into output array to write data
     *
     * @return number of bytes written to output
     *
     * @throws ShortBufferException if output buffer is too small
     */
    public synchronized int update(byte[] input, int offset, int length,
        byte[] output, int outputOffset) throws ShortBufferException {

        willUseKey();

        if (outputOffset + length > output.length)
            throw new ShortBufferException(
                    "output buffer is too small to hold the result.");

        return native_update(opmode, input, offset, length, output,
                outputOffset);
    }

    /**
     * Block cipher update operation
     *
     * @param input input data buffer for update
     * @param output output buffer to place data
     *
     * @return number of bytes written to output
     *
     * @throws ShortBufferException if output buffer is not large enough
     */
    public synchronized int update(ByteBuffer input, ByteBuffer output)
        throws ShortBufferException {

        willUseKey();

        int ret = 0;

        if (output.remaining() < input.remaining())
            throw new ShortBufferException(
                    "output buffer is too small to hold the result.");

        ret = native_update(opmode, input, input.position(), input.remaining(),
                output, output.position());

        input.position(input.position() + ret);
        output.position(output.position() + ret);

        return ret;
    }

    @Override
    public synchronized void releaseNativeStruct() {

        /* reset state first, then free */
        state = WolfCryptState.UNINITIALIZED;
        setNativeStruct(NULL);
    }

    /**
     * Return number of PKCS#7 pad bytes required given input size.
     *
     * @param inputSize size to calculate needed PKCS#7 pad bytes
     * @param blockSize Block size of algorithm being used
     *
     * @return Number of PKCS#7 pad bytes that would be appended to an input
     *         of size inputSize.
     */
    public static synchronized int getPKCS7PadSize(int inputSize,
        int blockSize) {

        int padSz = 0;

        if (inputSize == 0 || blockSize == 0) {
            throw new WolfCryptException(
                "Input or block size is 0");
        }

        padSz = blockSize - (inputSize % blockSize);

        return padSz;
    }

    /**
     * Pad input data with PKCS#7 padding.
     *
     * @param in Input data to be padded
     * @param blockSize Block size of algorithm being used
     *
     * @return Byte array which includes PKCS#7 padding on end
     *
     * @throws WolfCryptException if input is null, zero length,
     *         or blockSize is invalid
     */
    public static synchronized byte[] padPKCS7(byte[] in, int blockSize)
        throws WolfCryptException {

        int padSz = 0;
        byte[] padded = null;

        if (in == null) {
            throw new WolfCryptException(
                "Input array is null");
        }

        if (blockSize == 0) {
            throw new WolfCryptException("Block size is 0");
        }

        padSz = blockSize - (in.length % blockSize);
        padded = new byte[in.length + padSz];

        System.arraycopy(in, 0, padded, 0, in.length);

        try {
            Arrays.fill(padded, in.length, padded.length, (byte)(padSz & 0xff));
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            throw new WolfCryptException(e);
        }

        return padded;
    }

    /**
     * Unpad PKCS#7-padded data.
     *
     * @param in Input data which includes PKCS#7 padding on end
     * @param blockSize Block size of algorithm being used
     *
     * @return Byte array with PKCS#7 padding removed
     *
     * @throws WolfCryptException if input is null, zero length,
     *         or blockSize is invalid
     */
    public static synchronized byte[] unPadPKCS7(byte[] in, int blockSize) {

        byte padValue = 0;
        byte[] unpadded = null;
        boolean valid = true;

        if (in == null || in.length == 0) {
            throw new WolfCryptException(
                "Input array is null or zero length");
        }

        if (blockSize == 0) {
            throw new WolfCryptException("Block size is 0");
        }

        padValue = in[in.length - 1];

        /* verify pad value is less than or equal to block size */
        if (padValue > (byte)blockSize) {
            throw new WolfCryptException(
                "Invalid pad value, larger than block size");
        }

        /* verify pad bytes are consistent */
        for (int i = in.length; i > in.length - padValue; i--) {
            if (in[i - 1] != padValue) {
                valid = false;
            }
        }

        unpadded = new byte[in.length - padValue];
        System.arraycopy(in, 0, unpadded, 0, in.length - padValue);

        if (!valid) {
            throw new WolfCryptException(
                "Invalid PKCS#7 padding, pad bytes not consistent");
        }

        return unpadded;
    }
}

