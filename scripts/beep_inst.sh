#!/bin/bash

BEEP_ROOT="$(readlink -f $(dirname "$0")/..)"
PIN="$BEEP_ROOT"/pin/pin.sh
[ "$PEBIL_ROOT" != "" ] || . "$BEEP_ROOT"/PEBIL/bashrc
export LD_LIBRARY_PATH="$BEEP_ROOT"/pintool/obj-intel64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

# sanity checks
[ "$1" = "" ] && echo "No binary specified." && exit 1
[ ! -d ./BEEP_out ] && echo "No BEEP_out dir present. Aborting." && exit 1


# set variables
BASE_BINARY="$(basename "$1")"
if [ "$2" != "" ]; then
	# Use a specific log.
	PINLOG="$(ls -t ./BEEP_out/"$BASE_BINARY".*.pinout."$2" 2>/dev/null | head -1)"
else
	# Use the last log.
	PINLOG="$(ls -t ./BEEP_out/"$BASE_BINARY".*.pinout.* 2>/dev/null | grep -v '\.out$' | head -1)"
fi
[ "$PINLOG" = "" ] && echo "No Pin log to process." && exit 1

# analyze log
"$BEEP_ROOT"/pintool/analyze_pin_log "$PINLOG"

# instrument binaries
"$PEBIL_ROOT"/bin/pebil --tool BEEP --inp "$PINLOG".out --app "$1"

