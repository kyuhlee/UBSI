#!/bin/bash

BEEP_ROOT="$(readlink -f $(dirname "$0")/..)"
PIN="$BEEP_ROOT"/pin/pin.sh
#[ "$PEBIL_ROOT" != "" ] || . "$BEEP_ROOT"/PEBIL/bashrc
export LD_LIBRARY_PATH="$BEEP_ROOT"/pintool/obj-intel64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

#"$PEBIL_ROOT"/bin/pebil --tool BEEP --app "$1"
time "$PIN" -t BEEP_training.so -- $@
