#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <openssl/bio.h>
#include <android/log.h>

using namespace std;
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "native-lib", __VA_ARGS__)

#include "generic_service/CKeGateWay.h"

std::string ConvertJString(JNIEnv* env, jstring str)
{
    // Convert Jstring to C++ std::string.
    if ( !str ) std::string();
    const jsize len = env->GetStringUTFLength(str);
    const char* strChars = env->GetStringUTFChars(str, (jboolean *)0);
    std::string Result(strChars, len);
    env->ReleaseStringUTFChars(str, strChars);
    return Result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_InitKeyExchange(
        JNIEnv *env,
        jobject /* this */) {
    // Test call native C program from java .
    std::string msg = "Call the native C lib to start the key exchange process.";
    return env->NewStringUTF(msg.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string filename = "QS_Encryption_key";
    return env->NewStringUTF(filename.c_str());
}

void OnShared(string ss, std::string sessionid) {
    static int key_id = 0;
    std::cout << "INFO: Shared secrets: KEY_ID = " << key_id << std::endl;
    //LOG(INFO) << "Shared secretes, KEY_ID = " << key_id;
    //BIO_dump_fp(stdout, ss.data(), ss.length());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_keyExchangeJNI(
        JNIEnv *env,
        jobject /* this */,
        jstring filepath) {
    std::string phonefilePath = ConvertJString(env, filepath);
    std::string errStr = "Key Exchange Error: Gateway fail to start.";
    std::string keyStr = "Key Exchange finished";
    std::string cfgfile(phonefilePath+"gw_Alice_app.cfg"), ipTablefile(phonefilePath+"IPTable.cfg");
    // Same as the service.IPC_service/KexService.cpp if CKeGateWay::Start return 0 means "Gateway fails to start!"
    LOGV("Ckegateway::start() call");
    if (CKeGateWay::Start(cfgfile, ipTablefile, phonefilePath, OnShared)){
        return env->NewStringUTF(errStr.c_str());
    }
    return env->NewStringUTF(keyStr.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_loadConfigfileJNI(
        JNIEnv *env,
        jobject /* this */,
        jstring filepath) {
    std::string phonefilePath = ConvertJString(env, filepath);

    std::ifstream inFile;
    inFile.open(phonefilePath); //open the input file
    std::stringstream strStream;
    strStream << inFile.rdbuf(); //read the file
    std::string data = strStream.str(); //str holds the content of the file

    return env->NewStringUTF(data.c_str());
}

