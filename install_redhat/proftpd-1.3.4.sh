#!/bin/bash
#Proftpd-1.3.4:
cd /home/kyuhlee/UBSI_patch
wget https://github.com/downloads/proftpd/proftpd.github.com/proftpd-1.3.4.tar.gz
tar xzvf proftpd-1.3.4.tar.gz
cd proftpd-1.3.4 && patch -p1 < ../proftpd-1.3.4.patch
./configure && make
sudo make install
#config - /usr/local/etc/proftpd.conf
cp /usr/local/sbin/proftpd /home/kyuhlee/TRACE/BIN

