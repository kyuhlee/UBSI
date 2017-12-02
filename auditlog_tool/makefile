CC=g++
CFLAGS=-g

EXECUTABLE=analyzelog mergelog sortlog

all: $(EXECUTABLE)

analyzelog: analyzelog.cc
		$(CC) $(CFLAGS) -o $@ $<

mergelog: mergelog.cc
		$(CC) $(CFLAGS) -o $@ $<

sortlog: sortlog.cc
		$(CC) $(CFLAGS) -o $@ $<

clean:
		rm -f $(EXECUTABLE)
