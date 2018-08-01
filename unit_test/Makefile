SRCS = $(wildcard *.cpp)
PROGS = $(patsubst %.cpp,%,$(SRCS))
CC=g++
CFLAGS = -g -lpthread

all: $(PROGS)

%: %.cpp
	$(CC)  -o $@ $< $(CFLAGS) 

clean:
	rm $(PROGS)
