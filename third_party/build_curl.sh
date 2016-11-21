#!/bin/bash

open_src_path=`pwd`
curl_dir="curl-7.49.1"
curl_lib=`pwd`/build/curl-7.49.1/lib
curl_include=`pwd`/build/curl-7.49.1/include/curl

cd $curl_dir
chmod 777 configure

./configure --prefix=/usr/local/curl --with-ssl=/usr/local/openssl --with-libssh2=/usr/local/libssh2

make clean 
make
make install

cd $open_src_path
mkdir -p $curl_lib
mkdir -p $curl_include
cp /usr/local/curl/lib/libcurl.so*  $curl_lib
cp $open_src_path/$curl_dir/include/curl/*.h $curl_include
