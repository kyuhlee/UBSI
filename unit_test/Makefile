SRCS = $(wildcard *.c)
PROGS = $(patsubst %.c,%,$(SRCS))
CC=gcc
CFLAGS = -g -lpthread

all: $(PROGS)

%: %.c 
	$(CC)  -o $@ $< $(CFLAGS) 

clean:
	rm $(PROGS)
