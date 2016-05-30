#!/bin/bash

USER_ID=$(id -u -n)
export PATH="/usr/local/bin:/usr/local/sbin:$PATH"

### Helpers ##############################################################
function fail() {
	echo 'Failed!'
	exit "$1"
}

function _sudo() {
	sudo env PATH="$PATH" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" $*
}


### Action ###############################################################
echo "Killing auditd..."
_sudo killall -9 auditd

if [ -d /var/log/audit ]; then
	echo "Cleaning up auditd logs..."
	_sudo rm -f /var/log/audit/* || fail 1
else
	echo "Creating auditd log dir..."
	_sudo mkdir -p /var/log/audit || fail 2
fi

echo "Starting auditd..."
_sudo auditd || fail 3

echo "Cleaning up auditd rules..."
_sudo auditctl -D || fail 4

echo "Applying new set of rules to auditd..."
_sudo auditctl -a exit,always -S 1 -S 2 -S 3 -S 18 -S 20 -S 296 -S 41 -S 42 -S 43 -S 44 -S 45 -S 46 -S 47 -S 56 -S 57 -S 58 -S 59 -S 2 -S 293 -S 22 -S 288 -S 0 -S 17 -S 19 -S 295 -S 82 -S 264 -S 87 -S 86 -S 62 -S 9 -S 10 -F uid=$USER_ID || fail 5

echo "ok"

#sudo auditctl -a exit,always -S 1 -S 3 -S 18 -S 20 -S 296 -S 2  -S 41 -S 43 -S 44 -S 45 -S 46 -S 47 -S 56 -S 57 -S 58 -S 59 -S 2 -S 293 -S 22 -S 288 -S 0 -S 17 -S 19 -S 295 -S 82 -S 264 -S 87 -S 86 -F success=1 -F auid!=0 -F euid=1000
