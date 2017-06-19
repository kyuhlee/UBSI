#!/bin/bash
#w3m-0.5.3
cd /home/kyuhlee/UBSI_patch
wget  https://github.com/ivmai/libatomic_ops/releases/download/v7.4.6/libatomic_ops-7.4.6.tar.gz
tar xzvf libatomic_ops-7.4.6.tar.gz
cd libatomic_ops-7.4.6
./configure && make
sudo make install
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

cd /home/kyuhlee/UBSI_patch
wget http://www.hboehm.info/gc/gc_source/gc-7.6.0.tar.gz
tar xzvf gc-7.6.0.tar.gz
cd gc-7.6.0
./configure && make
sudo make install
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

cd /home/kyuhlee/UBSI_patch
wget http://downloads.sourceforge.net/project/w3m/w3m/w3m-0.5.3/w3m-0.5.3.tar.gz
tar xzvf w3m-0.5.3.tar.gz
cd w3m-0.5.3 && patch -p2 < ../w3m-0.5.3.patch
./configure LIBS="-lX11 -ldl -lXext -lz" && make
cp ./w3m /home/kyuhlee/TRACE/BIN

