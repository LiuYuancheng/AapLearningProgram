#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_cmkcppapp_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "This is a Hello from C++ file native-lib";
    return env->NewStringUTF(hello.c_str());
}
