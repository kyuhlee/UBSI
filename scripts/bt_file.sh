#!/bin/bash

if [ ! -f "$1" -o ! -f "$2" ]; then
	printf 'Usage: %s <log> <file>\n' "$0" 2>&1
	exit 1
fi

BEEP_ROOT="$(readlink -f $(dirname "$0")/..)"
inode=$(ls -i "$2" | cut -d\  -f1)

"$BEEP_ROOT"/log_analyzer/bt_beep "$1" inode="$inode"

