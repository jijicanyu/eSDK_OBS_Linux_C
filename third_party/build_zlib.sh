#!/bin/bash

open_src_path=`pwd`
zlib_dir="zlib-1.2.8"
zlib_lib=`pwd`/build/zlib-1.2.8/lib
zlib_include=`pwd`/build/zlib-1.2.8/include

cd $zlib_dir
chmod 777 configure

./configure 

make clean 
make
make install

cd $open_src_path
mkdir -p $zlib_lib
mkdir -p $zlib_include
cp /usr/local/lib/libz.so*  $zlib_lib
cp $open_src_path/$zlib_dir/contrib/minizip/*.h $zlib_include
cp $open_src_path/$zlib_dir/contrib/minizip/ioapi.c $zlib_include
cp $open_src_path/$zlib_dir/zconf.h $zlib_include
cp $open_src_path/$zlib_dir/zlib.h $zlib_include
