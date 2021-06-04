# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

file(GLOB mainSOURCE "generic_service/*.cpp")
file(GLOB KemsSOURCE "generic_service/kems/*.cpp" )
file(GLOB KepsSOURCE  "generic_service/keps/*.cpp")
file(GLOB LKepsSOURCE  "generic_service/lower_keps/*.cpp")
file(GLOB CommSOURCE  "generic_service/comm/*.cpp")
#file(GLOB bikeSOURCE  "generic_service/externals/bike1_128_cpa/*.c")
file(GLOB_RECURSE extendSrc "generic_service/externals/*.cpp" )

#file(GLOB_RECURSE extendSrc "generic_service/externals/*.cpp" )


file(GLOB NTLSOURCE  "ntlSrc/*.cpp")

link_directories(${CMAKE_SOURCE_DIR}/generic_service)

add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

            # add the related function's cpp file here
            #${CMAKE_SOURCE_DIR}/generic_service/CGatewayConfig.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/CKeGateWay.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/comm/CKeConn.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/comm/CTcpComm.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/kems/CRsaKem.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/kems/CBikeKem.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/kems/CFrodoKem.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/keps/CKepPhi.cpp
            #${CMAKE_SOURCE_DIR}/generic_service/keps/CKepPsiPrime.cpp
            ${CMAKE_SOURCE_DIR}/generic_service/externals/fips202.c
            ${CommSOURCE}
            ${KemsSOURCE}
            ${KepsSOURCE}
            ${LKepsSOURCE}
            #${bikeSOURCE}
            ${extendSrc}
            #${NTLSOURCE}
            #${CMAKE_SOURCE_DIR}/NIST_PQC_Round_2/KEM/BIKE/bike1_128_cca/kem.c
            ${mainSOURCE}

             # Provides a relative path to your source file(s).
             native-lib.cpp )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       native-lib

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

include_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(${CMAKE_SOURCE_DIR}/include)
#include_directories(${CMAKE_SOURCE_DIR}/include/openssl)
target_link_libraries(native-lib


        ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libgf2x.so
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libgmp.so
        ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libgmp.so
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libmbedcrypto.a
        ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libmbedtls.a
        ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libssl.a
        ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libcrypto.a
        ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libntl.a
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig.a
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig.so
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig.so
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig.so.9
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig.so.9.2.0
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig.so.11
        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig.so.11.0.2

        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig++.a


        #${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libconfig++.a
        )