# Sample toolchain file for building with gcc compiler
# 1) Download android NDK
# 2) Run cmake -H. -B_build -DCMAKE_TOOLCHAIN_FILE="${PWD}/toolchains/android.cmake"
# Notes:
# android api 28 requried as seen from $ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/glob.h
# or disable BUILD_TESTING in cmake config
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 28) # API level
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_NDK /home/test/Documents/android-ndk-r21d)
set(CMAKE_ANDROID_STL_TYPE c++_static)


