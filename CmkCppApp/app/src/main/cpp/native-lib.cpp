#include <jni.h>
#include <string>
#include <iostream>
#include "24string.hpp"
#include "24linkList.hpp"
//#include "IPC_KE_Service_Client"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_InitKeyExchange(
        JNIEnv *env,
        jobject /* this */) {
    std::string filename = "etst";
    return env->NewStringUTF(filename.c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string filename = "QS_Encryption_key";
    return env->NewStringUTF(filename.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_keyExchangeJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string keyStr = "biXhp3Ha1fgxVEp48zHrvVoXMStmxPuAPHo3TVz5lHU=";
    return env->NewStringUTF(keyStr.c_str());
}