CC=g++
CFLAGS=-g

EXECUTABLE=analyzelog mergelog sortlog count_kill spadeAuditBridge UBSI_auditBridge

all: $(EXECUTABLE)

analyzelog: analyzelog.cc
		$(CC) $(CFLAGS) -o $@ $<

mergelog: mergelog.cc
		$(CC) $(CFLAGS) -o $@ $<

sortlog: sortlog.cc
		$(CC) $(CFLAGS) -o $@ $<

count_kill: count_kill.cc
		$(CC) $(CFLAGS) -o $@ $<

UBSI_auditBridge: UBSI_auditBridge.cc UBSI_auditBridge.h UBSI_utils.cc UBSI_utils.h UBSI_csv.cc UBSI_csv.h
		$(CC) $(CFLAGS) -o $@ UBSI_auditBridge.cc UBSI_utils.cc UBSI_csv.cc

spadeAuditBridge: spadeAuditBridge.c
		gcc $(CFLAGS) -o $@ $<

clean:
		rm -f $(EXECUTABLE)
