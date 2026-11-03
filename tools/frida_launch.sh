#!/system/bin/sh
# Launch frida-server inside the guest with a full Android environment
# inherited from adbd (frida needs BOOTCLASSPATH/APEX roots for its JVM).
export PATH=/system/bin:/system/xbin:/system/sbin
adbd_pid=$(ps -A | grep -w adbd | grep -v grep | head -1 | tr -s ' ' | cut -d' ' -f2)
if [ -z "$adbd_pid" ]; then
  echo "adbd not found" >&2
  exit 11
fi
tr '\0' '\n' < "/proc/$adbd_pid/environ" > /data/local/tmp/.adbenv
while IFS= read -r line; do
  case "$line" in
    *=*) export "$line" ;;
  esac
done < /data/local/tmp/.adbenv
exec /data/local/tmp/.logd_helper -l 0.0.0.0:27042
