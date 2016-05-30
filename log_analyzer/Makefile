all: bt_beep fs_beep bt_audit fs_audit auditlog_sort

CPPFLAGS=-Wformat=0
SOURCES=auditlog.cpp graph.cpp unit.cpp init_scan.cpp backward_search.cpp tainted_track.cpp target.cpp
HEADERS=auditlog.h tainted_track.h target.h

FORWARD_SOURCES=auditlog.cpp graph.cpp unit.cpp forward_search.cpp tainted_track.cpp target.cpp init_scan.cpp

auditlog_sort: auditlog_sort.cpp
		g++ auditlog_sort.cpp -g -o auditlog_sort

bt_beep: $(SOURCES) $(HEADERS)
	g++ $(SOURCES) -g -o bt_beep $(CPPFLAGS)

bt_audit: $(SOURCES) $(HEADERS)
	g++ $(SOURCES) -g -o bt_audit -DWITHOUT_UNIT $(CPPFLAGS)

fs_beep: $(FORWARD_SOURCES) $(HEADERS)
	g++ $(FORWARD_SOURCES) -g -o fs_beep $(CPPFLAGS)

fs_audit: $(FORWARD_SOURCES) $(HEADERS)
	g++ $(FORWARD_SOURCES) -g -o fs_audit -DWITHOUT_UNIT $(CPPFLAGS)

clean:
	rm -f fs_beep fs_audit bt_beep bt_audit auditlog_sort
