#!/bin/bash
# httpd-2.4.20:
cd /home/kyuhlee/UBSI_patch
wget http://mirror.stjschools.org/public/apache//apr/apr-1.6.2.tar.gz
tar xzvf apr-1.6.2.tar.gz
cd apr-1.6.2
./configure && make
sudo make install

cd /home/kyuhlee/UBSI_patch
wget http://mirror.stjschools.org/public/apache//apr/apr-util-1.6.0.tar.gz
tar xzvf apr-util-1.6.0.tar.gz
cd apr-util-1.6.0
./configure --with-apr=/home/kyuhlee/UBSI_patch/apr-1.6.2 && make
sudo make install

cd /home/kyuhlee/UBSI_patch
wget https://ftp.pcre.org/pub/pcre/pcre-8.40.tar.gz
tar xzvf pcre-8.40.tar.gz 
cd pcre-8.40/
./configure && make 
sudo make install

cd /home/kyuhlee/UBSI_patch
wget https://archive.apache.org/dist/httpd/httpd-2.4.20.tar.gz
tar xzvf httpd-2.4.20.tar.gz
cd httpd-2.4.20 && patch -p1 < ../httpd-2.4.20.patch
./configure -with-mpm=worker && make 
sudo make install
cp /usr/local/apache2/bin/httpd /home/kyuhlee/TRACE/BIN
sudo cp /home/kyuhlee/UBSI_patch/httpd.conf /usr/local/apache2/conf/httpd.conf

#executable - /usr/local/apache2/bin/httpd
#config - /usr/local/apache2/conf/httpd.conf

#add the following lines in "/usr/local/apache2/conf/httpd.conf" file for multi-thread workers:
#	   LoadModule unixd_module modules/mod_unixd.so
#	   LoadModule access_compat_module modules/mod_access_compat.so
#	   ServerLimit         16
#	   StartServers         2
#	   MaxRequestWorkers  150
#	   MinSpareThreads     25
#	   MaxSpareThreads     75
#	   ThreadsPerChild     25

