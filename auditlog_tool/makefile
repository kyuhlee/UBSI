CC=g++
CFLAGS=-g

EXECUTABLE=analyzelog mergelog sortlog count_kill spadeAuditBridge

all: $(EXECUTABLE)

analyzelog: analyzelog.cc
		$(CC) $(CFLAGS) -o $@ $<

mergelog: mergelog.cc
		$(CC) $(CFLAGS) -o $@ $<

sortlog: sortlog.cc
		$(CC) $(CFLAGS) -o $@ $<

count_kill: count_kill.cc
		$(CC) $(CFLAGS) -o $@ $<

spadeAuditBridge: spadeAuditBridge.c
		gcc $(CFLAGS) -o $@ $<

clean:
		rm -f $(EXECUTABLE)
