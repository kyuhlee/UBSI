#!/bin/bash

if [ ! -f "$1" ]; then
	printf 'Usage: %s <log> <procname>\n' "$0" 2>&1
	exit 1
fi

BEEP_ROOT="$(readlink -f $(dirname "$0")/..)"

function get_pid() {
	# sed line explanation:
	# 	- keep only pid and exe name
	#	- '-n' surpresses output
	#	- trailing 'p' explicitely prints matching lines,
	#	  skipping non-matching lines
	sed -n 's/.*pid=\(\S*\) .*exe="\(\S*\)".*/\1 \2/p' "$1" |\
		sort -n |\
		uniq |\
		grep "$2".beep |\
		cut -d\  -f1
}


pid=$(get_pid "$1" "$2")

"$BEEP_ROOT"/log_analyzer/fs_beep "$1" pid="$pid"

