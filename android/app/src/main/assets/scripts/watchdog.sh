#!/system/bin/sh
# AIGuard 看门狗：守护进程退出后自动重启（短时间内反复退出时按 2、4、8…30 秒退避）。
# 守护进程被杀时防火墙规则留在内核里，重启期间仍然生效
DIR=/data/adb/aiguard
PIDFILE="$DIR/run/watchdog.pid"
mkdir -p "$DIR/run" "$DIR/logs"

if [ -f "$PIDFILE" ]; then
  old="$(cat "$PIDFILE" 2>/dev/null)"
  if [ -n "$old" ] && [ "$old" != "$$" ] && grep -q "aiguard/watchdog.sh" "/proc/$old/cmdline" 2>/dev/null; then
    exit 0
  fi
fi
echo $$ > "$PIDFILE"

fails=0
while true; do
  [ -f "$DIR/uninstalling" ] && break
  [ -f "$DIR/aiguard.apk" ] || break
  started=$(date +%s)
  CLASSPATH="$DIR/aiguard.apk" /system/bin/app_process /system/bin --nice-name=aiguardd \
    com.aiguard.daemon.DaemonMain >> "$DIR/logs/daemon.out" 2>&1
  code=$?
  [ -f "$DIR/uninstalling" ] && break
  ran=$(( $(date +%s) - started ))
  if [ "$ran" -lt 30 ]; then
    fails=$((fails + 1))
  else
    fails=0
  fi
  wait_s=1
  i=0
  while [ "$i" -lt "$fails" ] && [ "$wait_s" -lt 30 ]; do wait_s=$((wait_s * 2)); i=$((i + 1)); done
  [ "$wait_s" -gt 30 ] && wait_s=30
  echo "$(date '+%F %T') aiguardd 退出（$code），${wait_s} 秒后重启" >> "$DIR/logs/watchdog.log"
  sleep "$wait_s"
done
rm -f "$PIDFILE"
