#!/bin/bash
#wget-1.17.1:
cd /home/kyuhlee/UBSI_patch
wget http://ftp.gnu.org/gnu/wget/wget-1.17.1.tar.gz
tar xzvf wget-1.17.1.tar.gz
cd wget-1.17.1 && patch -p1 < ../wget-1.17.1.patch
./configure && make
cp src/wget /home/kyuhlee/TRACE/BIN


