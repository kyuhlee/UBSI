#!/bin/bash

BEEP_ROOT="$(readlink -f $(dirname "$0")/..)"
PIN="$BEEP_ROOT"/pin/pin.sh
export LD_LIBRARY_PATH="$BEEP_ROOT"/pintool/obj-intel64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$PIN" -t identify_loops.so -- $@
