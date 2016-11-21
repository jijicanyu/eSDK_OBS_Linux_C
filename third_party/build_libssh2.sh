#!/bin/bash

open_src_path=`pwd`
libssh2_dir="libssh2-1.7.0"
libssh2_lib=`pwd`/build/libssh2-1.7.0/lib
libssh2_include=`pwd`/build/libssh2-1.7.0/include

cd $libssh2_dir
chmod 777 configure

./configure --prefix=/usr/local/libssh2 CPPFLAGS="-I/usr/local/openssl/include" LDFLAGS="-L/usr/local/openssl/lib"

make clean 
make
make install

cd $open_src_path
mkdir -p $libssh2_lib
mkdir -p $libssh2_include
cp /usr/local/libssh2/lib/libssh2.so*  $libssh2_lib
cp $open_src_path/$libssh2_dir/include/*.h $libssh2_include
