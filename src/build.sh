#!/bin/bash
#Usage: build.sh
#OBS_API目录下生成include、lib三个文件

# ├─include
# └─lib
#----------------------- variables --------------------#
#当前脚本所在路径
G_CWD=`dirname $0`
pushd $G_CWD >/dev/null
G_CWD=`pwd`
popd >/dev/null

G_FILE_NAME=$0
G_BUILD_OPTION=release
G_BUILD_DIR=${G_CWD}
g_PATH=build

#----------------------- compile -----------------------#
make clean
make

if [ -d OBS_API ];then
    rm -rf OBS_API
fi

mkdir OBS_API

mkdir OBS_API/include
mkdir OBS_API/lib

cp -f ${g_PATH}/include/* OBS_API/include
cp -f ${g_PATH}/lib/*.so OBS_API/lib
cp -f ./../self_dev/eSDK_LogAPI_V2.1.00/lib/libeSDKLogAPI.so OBS_API/lib
cp -f ./../third_party/build/curl-7.49.1/lib/* OBS_API/lib
cp -f ./../third_party/build/libxml2-2.9.4/lib/* OBS_API/lib
cp -f ./../third_party/build/openssl-1.0.2j/lib/* OBS_API/lib
cp -f ./../third_party/build/pcre-8.39/lib/* OBS_API/lib
cp -f ./../third_party/build/libssh2-1.7.0/lib/* OBS_API/lib
cp -f OBS.ini OBS_API/lib

make clean
