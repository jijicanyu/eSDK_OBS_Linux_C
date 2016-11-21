#!/bin/bash

open_src_path=`pwd`
pcre_dir="pcre-8.39"
pcre_lib=`pwd`/build/pcre-8.39/lib
pcre_include=`pwd`/build/pcre-8.39/include/pcre

cd $pcre_dir
chmod 777 configure

./configure --prefix=/usr/local/pcre 

make clean 
make
make install

cd $open_src_path
mkdir -p $pcre_lib
mkdir -p $pcre_include
cp /usr/local/pcre/lib/*.so*  $pcre_lib
cp /usr/local/pcre/include/*.h $pcre_include
