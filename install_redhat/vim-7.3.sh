#!/bin/bash
#vim-7.3:
cd /home/kyuhlee/UBSI_patch
wget ftp://ftp.vim.org/pub/vim/unix/vim-7.3.tar.bz2
bunzip2 vim-7.3.tar.bz2 && tar xvf vim-7.3.tar
cd vim73 && patch -p1 < ../vim73.patch
./configure && make
cp src/vim /home/kyuhlee/TRACE/BIN
#executable - src/vim

