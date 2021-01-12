# Set directory
SCRIPTPATH=`realpath .`
export ANDROID_NDK_ROOT=${SCRIPTPATH}/android-ndk-r21d
OPENSSL_DIR=${SCRIPTPATH}/openssl-3.0.0-alpha9
toolchains_path=$(python toolchains_path.py --ndk ${ANDROID_NDK_ROOT})
# Set compiler clang, instead of gcc by default
CC=clang
#Add toolchains bin directory to PATH
PATH=$toolchains_path/bin:$PATH
# Set the Android API levels
ANDROID_API=28
# Set the target architecture
# Can be android-arm, android-arm64, android-x86, android-x86 etc
architecture=android-arm64
# Create the make file
cd ${OPENSSL_DIR}
./Configure ${architecture} -D__ANDROID_API__=$ANDROID_API
make
