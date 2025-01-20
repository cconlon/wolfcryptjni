/* jni_aes.c
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

#include <stdint.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/aes.h>

#include <com_wolfssl_wolfcrypt_Aes.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Aes_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifndef NO_AES
    Aes* aes = NULL;

    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Aes object");
    }
    else {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    LogStr("new Aes() = %p\n", aes);

    return (jlong)(uintptr_t)aes;

#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Aes_native_1set_1key_1internal(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object,
    jint opmode)
{
#ifndef NO_AES
    int ret = 0;
    Aes* aes  = NULL;
    byte* key = NULL;
    byte* iv  = NULL;
    word32 keySz = 0;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key = getByteArray(env, key_object);
    iv  = getByteArray(env, iv_object);
    keySz = getByteArrayLength(env, key_object);

    ret = (!aes || !key) /* iv is optional */
        ? BAD_FUNC_ARG
        : wc_AesSetKey(aes, key, keySz, iv, opmode);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_AesSetKey(aes=%p, key=%p, iv=%p, opmode) = %d\n",
        aes, key, iv, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_Aes_native_1update_1internal__I_3BII_3BI(
    JNIEnv* env, jobject this, jint opmode,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
#ifndef NO_AES
    int ret = 0;
    Aes*  aes    = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getByteArray(env, input_object);
    output = getByteArray(env, output_object);

    if (!aes || !input || !output) {
        ret = BAD_FUNC_ARG; /* NULL sanitizers */
    }
    else if (offset < 0 || length < 0 || outputOffset < 0) {
        ret = BAD_FUNC_ARG; /* signed sanizizers */
    }
    else if (length == 0) {
        ret = 0;
    } else if ((word32)(offset + length) >
             getByteArrayLength(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getByteArrayLength(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == AES_ENCRYPTION) {
        ret = wc_AesCbcEncrypt(aes, output+outputOffset, input+offset, length);
        LogStr("wc_AesCbcEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }
    else {
        ret = wc_AesCbcDecrypt(aes, output+outputOffset, input+offset, length);
        LogStr("wc_AesCbcDecrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input, offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output + outputOffset);
    LogHex((byte*) output, outputOffset, length);

    releaseByteArray(env, input_object, input, JNI_ABORT);
    releaseByteArray(env, output_object, output, ret);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_Aes_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jint opmode,
    jobject input_object, jint offset, jint length,
    jobject output_object, jint outputOffset)
{
    int ret = 0;

#ifndef NO_AES
    Aes*  aes    = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getDirectBufferAddress(env, input_object);
    output = getDirectBufferAddress(env, output_object);

    if (!aes || !input || !output) {
        ret = BAD_FUNC_ARG; /* NULL sanitizers */
    }
    else if (offset < 0 || length < 0) {
        ret = BAD_FUNC_ARG; /* signed sanizizers */
    }
    else if ((word32)(offset + length) >
             getDirectBufferLimit(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getDirectBufferLimit(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == AES_ENCRYPTION) {
        ret = wc_AesCbcEncrypt(aes, output, input + offset, length);
        LogStr("wc_AesCbcEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }
    else {
        ret = wc_AesCbcDecrypt(aes, output, input + offset, length);
        LogStr("wc_AesCbcDecrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input, offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output);
    LogHex((byte*) output, 0, length);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

