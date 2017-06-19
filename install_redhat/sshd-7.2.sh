#!/bin/bash
#Sshd-7.2p2: 
cd /home/kyuhlee/UBSI_patch
wget http://ftp.vim.org/security/OpenSSH/openssh-7.2p2.tar.gz
tar xzvf openssh-7.2p2.tar.gz
cd openssh-7.2p2 && patch -p1 < ../openssh-7.2p2.patch
./configure && make
sudo make install
# config -  /usr/local/etc/sshd_config
cp /usr/local/sbin/sshd /home/kyuhlee/TRACE/BIN
cp /usr/local/bin/ssh /home/kyuhlee/TRACE/BIN


