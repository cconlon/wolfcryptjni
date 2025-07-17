/* NativeStruct.java
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

/**
 * Wrapper for the native WolfCrypt structs.
 */
public abstract class NativeStruct extends WolfObject {

    /** Logical mapping of NULL to 0 */
    public static final long NULL = 0;

    /**
     * Create new NativeStruct object
     */
    protected NativeStruct() {
        /* Native struct allocated in initNativeStruct() upon subclass init */
    }

    /* points to the internal native structure */
    private volatile long pointer = 0;

    /** Lock around native pointer use */
    protected final Object pointerLock = new Object();

    /**
     * Allocate and initialize native struct.
     */
    protected void initNativeStruct() {
        synchronized (pointerLock) {
            if (pointer == 0) {
                setNativeStruct(mallocNativeStruct());
            }
        }
    }

    /**
     * Get pointer to wrapped native structure
     *
     * WARNING: the pointer returned from this function has not been locked
     * and may cause threading synchronization issues if used in a
     * multi-threaded use case or application.
     *
     * @return pointer to native structure
     */
    public long getNativeStruct() {
        synchronized (pointerLock) {
            return this.pointer;
        }
    }

    /**
     * Set pointer to native structure
     *
     * If NativeStruct already holds pointer, old pointer will be free()'d
     * before resetting to new pointer. Callers of this method should
     * synchronize on 'pointerLock' before calling this method.
     *
     * @param nativeStruct pointer to initialized native structure
     */
    private void setNativeStruct(long nativeStruct) {

        if (this.pointer != NULL) {
            xfree(this.pointer);
        }

        this.pointer = nativeStruct;
    }

    /**
     * Releases the host data stored in a NativeStruct.
     *
     * This method provides a way to release host data without depending on the
     * garbage collector to get around to releasing it. Derived objects whose
     * native data structures have their own free functions, should be override
     * this method to call that function.
     */
    public void releaseNativeStruct() {
        synchronized (pointerLock) {
            setNativeStruct(NULL);
        }
    }

    /**
     * Malloc native structure pointer
     *
     * @return allocated pointer to native structure
     *
     * @throws OutOfMemoryError if native malloc fails with memory error
     */
    protected abstract long mallocNativeStruct() throws OutOfMemoryError;

    private native void xfree(long pointer);

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        releaseNativeStruct();

        super.finalize();
    }
}

