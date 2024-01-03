//
// Created by Administrator on 2019/1/29/029.
//

#include <jni.h>
#include <stddef.h>
#include "lib/raop.h"
#include "log.h"
#include "lib/stream.h"
#include "lib/logger.h"
#include <malloc.h>
#include <cstring>

static JavaVM* g_JavaVM;

void OnRecvAudioData(void *observer, pcm_data_struct *data, const char* remoteDeviceName, const char* remoteDeviceId) {
    jobject obj = (jobject) observer;
    JNIEnv* jniEnv = NULL;
    g_JavaVM->AttachCurrentThread(&jniEnv, NULL);
    jclass cls = jniEnv->GetObjectClass(obj);
    jmethodID onRecvAudioDataM = jniEnv->GetMethodID(cls, "onRecvAudioData", "([SJLjava/lang/String;Ljava/lang/String;)V");
    jniEnv->DeleteLocalRef(cls);
    jshortArray sarr = jniEnv->NewShortArray(data->data_len);
    if (sarr == NULL) return;
    jniEnv->SetShortArrayRegion(sarr, (jint) 0, data->data_len, (jshort *) data->data);

    jstring deviceName = jniEnv->NewStringUTF(remoteDeviceName);
    jstring deviceId = jniEnv->NewStringUTF(remoteDeviceId);

    jniEnv->CallVoidMethod(obj, onRecvAudioDataM, sarr, data->pts,deviceName, deviceId);
    jniEnv->DeleteLocalRef(sarr);
    g_JavaVM->DetachCurrentThread();
}

void OnRecvVideoData(void *observer, h264_decode_struct *data, const char* remoteDeviceName, const char* remoteDeviceId) {
    jobject obj = (jobject) observer;
    JNIEnv* jniEnv = NULL;
    g_JavaVM->AttachCurrentThread(&jniEnv, NULL);
    jclass cls = jniEnv->GetObjectClass(obj);
    jmethodID onRecvVideoDataM = jniEnv->GetMethodID(cls, "onRecvVideoData", "([BIJJLjava/lang/String;Ljava/lang/String;)V");
    jniEnv->DeleteLocalRef(cls);
    jbyteArray barr = jniEnv->NewByteArray(data->data_len);
    if (barr == NULL) return;
    jniEnv->SetByteArrayRegion(barr, (jint) 0, data->data_len, (jbyte *) data->data);

    jstring deviceName = jniEnv->NewStringUTF(remoteDeviceName);
    jstring deviceId = jniEnv->NewStringUTF(remoteDeviceId);

    jniEnv->CallVoidMethod(obj, onRecvVideoDataM, barr, data->frame_type,
                                         data->nTimeStamp, data->pts,
                                         deviceName, deviceId);
    jniEnv->DeleteLocalRef(barr);
    g_JavaVM->DetachCurrentThread();
}

void OnDeviceDisconnected(void *observer, const char* remoteDeviceName, const char* remoteDeviceId) {
    jobject obj = (jobject) observer;
    JNIEnv* jniEnv = NULL;
    g_JavaVM->AttachCurrentThread(&jniEnv, NULL);
    jclass cls = jniEnv->GetObjectClass(obj);
    jmethodID onDeviceDisconnectedM = jniEnv->GetMethodID(cls, "onDeviceDisconnected", "(Ljava/lang/String;Ljava/lang/String;)V");
    jniEnv->DeleteLocalRef(cls);

    jstring deviceName = jniEnv->NewStringUTF(remoteDeviceName);
    jstring deviceId = jniEnv->NewStringUTF(remoteDeviceId);

    jniEnv->CallVoidMethod(obj, onDeviceDisconnectedM,
                           deviceName, deviceId);

    g_JavaVM->DetachCurrentThread();
}

void OnDeviceConnected(void *observer, const char* remoteDeviceName, const char* remoteDeviceId) {
    jobject obj = (jobject) observer;
    JNIEnv* jniEnv = NULL;
    g_JavaVM->AttachCurrentThread(&jniEnv, NULL);
    jclass cls = jniEnv->GetObjectClass(obj);
    jmethodID onDeviceConnectedM = jniEnv->GetMethodID(cls, "onDeviceConnected", "(Ljava/lang/String;Ljava/lang/String;)V");
    jniEnv->DeleteLocalRef(cls);

    jstring deviceName = jniEnv->NewStringUTF(remoteDeviceName);
    jstring deviceId = jniEnv->NewStringUTF(remoteDeviceId);

    jniEnv->CallVoidMethod(obj, onDeviceConnectedM,
                           deviceName, deviceId);

    g_JavaVM->DetachCurrentThread();
}

void OnSetAudioVolume(void *observer, float volume, const char* remoteDeviceName, const char* remoteDeviceId) {
    jobject obj = (jobject) observer;
    JNIEnv* jniEnv = NULL;
    g_JavaVM->AttachCurrentThread(&jniEnv, NULL);
    jclass cls = jniEnv->GetObjectClass(obj);
    jmethodID OnSetAudioVolumeM = jniEnv->GetMethodID(cls, "onSetAudioVolume", "([FLjava/lang/String;Ljava/lang/String;)V");
    jniEnv->DeleteLocalRef(cls);

    jstring deviceName = jniEnv->NewStringUTF(remoteDeviceName);
    jstring deviceId = jniEnv->NewStringUTF(remoteDeviceId);

    jniEnv->CallVoidMethod(obj, OnSetAudioVolumeM, volume, deviceName, deviceId);
    g_JavaVM->DetachCurrentThread();
}

extern "C" void
audio_process(void *cls, pcm_data_struct *data, const char* remoteDeviceName, const char* remoteDeviceId)
{
    OnRecvAudioData(cls, data, remoteDeviceName, remoteDeviceId);
}

extern "C" void
audio_set_volume(void *cls, void *opaque, float volume, const char* remoteName, const char* remoteDeviceId)
{

}

extern "C" void
video_process(void *cls, h264_decode_struct *data, const char* remoteDeviceName, const char* remoteDeviceId)
{
    OnRecvVideoData(cls, data, remoteDeviceName, remoteDeviceId);
}

extern "C" void
disconnected(void *cls, const char* remoteDeviceName, const char* remoteDeviceId)
{
    OnDeviceDisconnected(cls, remoteDeviceName, remoteDeviceId);
}

extern "C" void
connected(void *cls, const char* remoteDeviceName, const char* remoteDeviceId)
{
    OnDeviceConnected(cls, remoteDeviceName, remoteDeviceId);
}

extern "C" void
log_callback(void *cls, int level, const char *msg) {
    switch (level) {
        case LOGGER_DEBUG: {
            LOGD("%s", msg);
            break;
        }
        case LOGGER_WARNING: {
            LOGW("%s", msg);
            break;
        }
        case LOGGER_INFO: {
            LOGI("%s", msg);
            break;
        }
        case LOGGER_ERR: {
            LOGE("%s", msg);
            break;
        }
        default:break;
    }

}

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_JavaVM = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_fang_myapplication_RaopServer_start(JNIEnv* env, jobject object, jlong opaque) {
    raop_t *raop;
    raop_callbacks_t raop_cbs;
    memset(&raop_cbs, 0, sizeof(raop_cbs));
    raop_cbs.cls = (void *) env->NewGlobalRef(object);;
    raop_cbs.audio_process = audio_process;
    raop_cbs.audio_set_volume = audio_set_volume;
    raop_cbs.video_process = video_process;
    raop_cbs.connected = connected;
    raop_cbs.disconnected = disconnected;
    raop = raop_init(opaque, &raop_cbs);
    if (raop == NULL) {
        LOGE("raop = NULL");
        return 0;
    } else {
        LOGD("raop init success");
    }

    raop_set_log_callback(raop, log_callback, NULL);
    raop_set_log_level(raop, RAOP_LOG_DEBUG);

    unsigned short port = 0;
    raop_start(raop, &port);
    raop_set_port(raop, port);
    LOGD("raop port = % d", raop_get_port(raop));
    return (jlong) (void *) raop;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fang_myapplication_RaopServer_getPort(JNIEnv* env, jobject object, jlong opaque) {
    raop_t *raop = (raop_t *) (void *) opaque;
    return raop_get_port(raop);
}

extern "C" JNIEXPORT void JNICALL
Java_com_fang_myapplication_RaopServer_stop(JNIEnv* env, jobject object, jlong opaque) {
    raop_t *raop = (raop_t *) (void *) opaque;
    jobject obj = (jobject) raop_get_callback_cls(raop);
    raop_destroy(raop);
    env->DeleteGlobalRef(obj);
    LOGD("roap stopped");
}