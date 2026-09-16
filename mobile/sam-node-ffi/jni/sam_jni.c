// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

#include <jni.h>
#include "libsam.h"

#ifdef SAM_DEBUG
#include <stdlib.h>
#include <string.h>

// Byte arrays preserve UTF-8 paths/errors without JNI's modified-UTF-8 conversion.
static jbyteArray copy_and_free(JNIEnv *env, char *value) {
    if (value == NULL) return NULL;
    size_t length = strlen(value);
    jbyteArray result = (*env)->NewByteArray(env, (jsize)length);
    if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, (jsize)length, (jbyte *)value);
    FreeString(value);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamLocalTestNative_start(JNIEnv *env, jobject receiver, jbyteArray path) {
    (void)receiver;
    if (path == NULL) {
        jclass type = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (type != NULL) (*env)->ThrowNew(env, type, "SAM storage path is required");
        return NULL;
    }
    jsize length = (*env)->GetArrayLength(env, path);
    if (length <= 0 || length > 4096) {
        jclass type = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (type != NULL) (*env)->ThrowNew(env, type, "Invalid SAM storage path length");
        return NULL;
    }
    char *bytes = malloc((size_t)length + 1);
    if (bytes == NULL) {
        jclass type = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (type != NULL) (*env)->ThrowNew(env, type, "SAM path allocation failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, path, 0, length, (jbyte *)bytes);
    if ((*env)->ExceptionCheck(env)) { free(bytes); return NULL; }
    bytes[length] = '\0';
    if (memchr(bytes, '\0', (size_t)length) != NULL) {
        free(bytes);
        jclass type = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (type != NULL) (*env)->ThrowNew(env, type, "SAM storage path contains NUL");
        return NULL;
    }
    char *error = StartLocalTestNode(bytes);
    free(bytes);
    return copy_and_free(env, error);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamLocalTestNative_stop(JNIEnv *env, jobject receiver) {
    (void)receiver;
    return copy_and_free(env, StopLocalTestNode());
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamLocalTestNative_status(JNIEnv *env, jobject receiver) {
    (void)receiver;
    return copy_and_free(env, LocalTestNodeStatus());
}

// The JSON bridge is debug-only. Bound copies before entering Go and reject NUL.
static jbyteArray mesh_json_call(JNIEnv *env, jbyteArray input, char *(*call)(char *)) {
    jsize length = input == NULL ? 0 : (*env)->GetArrayLength(env, input);
    if (length <= 0 || length > 65536) {
        jclass type = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (type != NULL) (*env)->ThrowNew(env, type, "Invalid SAM JSON input length");
        return NULL;
    }
    char *bytes = malloc((size_t)length + 1);
    if (bytes == NULL) {
        jclass type = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (type != NULL) (*env)->ThrowNew(env, type, "SAM JSON allocation failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, input, 0, length, (jbyte *)bytes);
    if ((*env)->ExceptionCheck(env)) { free(bytes); return NULL; }
    bytes[length] = '\0';
    if (memchr(bytes, '\0', (size_t)length) != NULL) {
        free(bytes);
        jclass type = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (type != NULL) (*env)->ThrowNew(env, type, "SAM JSON contains NUL");
        return NULL;
    }
    char *result = call(bytes);
    free(bytes);
    return copy_and_free(env, result);
}
JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamMeshNative_start(JNIEnv *env, jobject receiver, jbyteArray input) {
    (void)receiver; return mesh_json_call(env, input, StartSharedMesh);
}
JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamMeshNative_stop(JNIEnv *env, jobject receiver) {
    (void)receiver; return copy_and_free(env, StopSharedMesh());
}
JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamMeshNative_status(JNIEnv *env, jobject receiver) {
    (void)receiver; return copy_and_free(env, SharedMeshStatus());
}
JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamMeshNative_discover(JNIEnv *env, jobject receiver) {
    (void)receiver; return copy_and_free(env, DiscoverSharedMeshTools());
}
JNIEXPORT jbyteArray JNICALL
Java_com_example_appfunctions_agent_sam_SamMeshNative_call(JNIEnv *env, jobject receiver, jbyteArray input) {
    (void)receiver; return mesh_json_call(env, input, CallSharedMeshTool);
}

#endif

// GetMeshInfo's current contract contains ASCII JSON (counters, peer ID or fixed
// errors). Free every C.CString through the library that allocated it, including
// when NewStringUTF fails with a pending OutOfMemoryError.
JNIEXPORT jstring JNICALL
Java_com_example_appfunctions_agent_sam_SamNativeDiagnostics_meshInfoJson(
    JNIEnv *env, jobject receiver) {
    (void)receiver;
    char *info = GetMeshInfo();
    if (info == NULL) {
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalStateException");
        if (exception != NULL) {
            (*env)->ThrowNew(env, exception, "SAM returned no diagnostic response");
        }
        return NULL;
    }
    jstring result = (*env)->NewStringUTF(env, info);
    FreeString(info);
    return result;
}
