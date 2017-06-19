#!/bin/bash
#pine-4.64
cd /home/kyuhlee/UBSI_patch
wget http://ftp.swin.edu.au/pine/pine.tar.gz
tar xzvf pine.tar.gz
cd pine4.64 && patch -p1 < ../pine4.64.patch
./build slx SSLDIR=/lib/x86_64-linux-gnu SSLINCLUDE=/usr/include/openssl
cp ./pine/pine /home/kyuhlee/TRACE/BIN


