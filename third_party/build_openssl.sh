#!/bin/bash

open_src_path=`pwd`
openssl_dir="openssl-1.0.2j"
openssl_lib=`pwd`/build/openssl-1.0.2j/lib
openssl_include=`pwd`/build/openssl-1.0.2j/include/openssl

cd $openssl_dir
chmod 777 config

./config threads shared --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/

make clean 
make
make install

cd $open_src_path
mkdir -p $openssl_lib
mkdir -p $openssl_include
cp /usr/local/openssl/lib/libcrypto.so*  $openssl_lib
cp /usr/local/openssl/lib/libssl.so*  $openssl_lib
cp $open_src_path/$openssl_dir/include/openssl/*.h $openssl_include
