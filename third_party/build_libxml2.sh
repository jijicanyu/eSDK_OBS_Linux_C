#!/bin/bash

open_src_path=`pwd`
libxml2_dir="libxml2-2.9.4"
libxml2_lib=`pwd`/build/libxml2-2.9.4/lib
libxml2_include=`pwd`/build/libxml2-2.9.4/include/libxml

cd $libxml2_dir
chmod 777 configure

./configure --prefix=/usr/local/libxml2

make clean 
make
make install

cd $open_src_path
mkdir -p $libxml2_lib
mkdir -p $libxml2_include
cp /usr/local/libxml2/lib/libxml2.so*  $libxml2_lib
cp $open_src_path/$libxml2_dir/include/*.h $libxml2_include/../
cp $open_src_path/$libxml2_dir/include/libxml/*.h $libxml2_include
