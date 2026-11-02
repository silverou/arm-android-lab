#!/bin/sh
# Run a command string inside the redroid guest.
# GUEST_MODE=docker (default) -> docker exec; adb -> adb shell.
# usage: gx.sh "<shell command>"
cmd="$1"
if [ "${GUEST_MODE:-docker}" = "adb" ]; then
  exec adb -s "${ADB_SERIAL}" shell "$cmd"
else
  exec sudo docker exec redroid /system/bin/sh -c \
    'export PATH=/system/bin:/system/xbin:/system/sbin:$PATH; '"$cmd"
fi
