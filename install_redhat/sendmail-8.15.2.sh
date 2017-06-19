#!/bin/bash
#Sendmail-8.15.2:
cd /home/kyuhlee/UBSI_patch
wget ftp://ftp.sendmail.org/pub/sendmail/sendmail.8.15.2.tar.gz
tar xzvf sendmail.8.15.2.tar.gz
cd sendmail-8.15.2 
chmod 644 devtools/OS/Linux
patch -p1 < ../sendmail-8.15.2.patch
cd sendmail && ./Build
sudo useradd smmsp
sudo mkdir -p /usr/man/man8 /usr/man/man1 /usr/man/man5 
sudo ./Build install
cp /usr/sbin/sendmail /home/kyuhlee/TRACE/BIN


