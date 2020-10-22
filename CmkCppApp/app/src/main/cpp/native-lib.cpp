#include <jni.h>
#include <string>
#include <iostream>
#include "24string.hpp"
#include "24linkList.hpp"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "This is a Hello from C++ file native-lib";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_keyExchangeJNI(
        JNIEnv* env,
jobject /* this */) {
std::string hello = "Button pressed and  start the key exchange";
return env->NewStringUTF(hello.c_str());
}