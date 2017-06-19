#!/bin/bash
#Yafc-1.1.1: 
cd /home/kyuhlee/UBSI_patch
wget http://downloads.sourceforge.net/project/yafc/yafc/yafc-1.1.1/yafc-1.1.1.tar.gz
tar xzvf yafc-1.1.1.tar.gz
cd yafc-1.1.1 && patch -p1 < ../yafc-1.1.1.patch
./configure && make
cp src/yafc /home/kyuhlee/TRACE/BIN


