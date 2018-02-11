EXECUTABLE=UBSI_bt AUDIT_bt UBSI_ft AUDIT_ft UBSI_print bridge

all: $(EXECUTABLE)

CC=g++
#CFLAGS=-Wformat=0
CFLAGS=-g
SOURCES=utils.cc init_scan.cc tables.cc graph.cc
HEADERS=utils.h tables.h init_scan.h graph.h

bridge:
		gcc bridge.c -o bridge
UBSI_print: $(SOURCES) $(HEADERS) UBSI_print.cc
	$(CC) UBSI_print.cc $(SOURCES) $(CFLAGS) -g -o $@

UBSI_bt: $(SOURCES) $(HEADERS) UBSI_bt.cc
	$(CC) UBSI_bt.cc $(SOURCES) $(CFLAGS) -g -o $@

AUDIT_bt: $(SOURCES) $(HEADERS) UBSI_bt.cc
	$(CC) UBSI_bt.cc $(SOURCES) $(CFLAGS) -DWITHOUT_UNIT -g -o $@

UBSI_ft: $(SOURCES) $(HEADERS) UBSI_ft.cc
	$(CC) UBSI_ft.cc $(SOURCES) $(CFLAGS) -g -o $@

AUDIT_ft: $(SOURCES) $(HEADERS) UBSI_ft.cc
	$(CC) UBSI_ft.cc $(SOURCES) $(CFLAGS) -DWITHOUT_UNIT -g -o $@

clean:
	rm -f $(EXECUTABLE)
