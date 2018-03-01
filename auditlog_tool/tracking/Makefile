EXECUTABLE=UBSI_bt AUDIT_bt UBSI_ft AUDIT_ft UBSI_print bridge UBSI_into_SQL

all: $(EXECUTABLE)

CC=g++
#CFLAGS=-Wformat=0
CFLAGS=-g
SOURCES=utils.cc init_scan.cc tables.cc graph.cc
HEADERS=utils.h tables.h init_scan.h graph.h

bridge: bridge.c
		gcc bridge.c -o bridge

UBSI_into_SQL: UBSI_into_SQL.cc process_dep.cc process_dep.h utils.cc utils.h
		$(CC) UBSI_into_SQL.cc process_dep.cc utils.cc $(CFLAGS) -o $@

UBSI_dep: $(SOURCES) $(HEADERS) UBSI_dep.cc
	$(CC) UBSI_dep.cc $(SOURCES) $(CFLAGS) -g -o $@

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
