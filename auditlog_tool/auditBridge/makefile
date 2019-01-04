CC=g++
CFLAGS=-g

EXECUTABLE=UBSI_auditBridge

all: $(EXECUTABLE)

UBSI_auditBridge: UBSI_auditBridge.cc UBSI_auditBridge.h UBSI_utils.cc UBSI_utils.h UBSI_csv.cc UBSI_csv.h
		$(CC) $(CFLAGS) -o $@ UBSI_auditBridge.cc UBSI_utils.cc UBSI_csv.cc

clean:
		rm -f $(EXECUTABLE)
