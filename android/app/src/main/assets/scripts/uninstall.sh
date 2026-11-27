#!/system/bin/sh
# AIGuard 卸载：停掉看门狗与守护进程，撤销防火墙、恢复 IPv6 与私人 DNS，删除开机脚本。
# 加 --purge 同时删除设置、订阅和日志
DIR=/data/adb/aiguard
touch "$DIR/uninstalling" 2>/dev/null
rm -f /data/adb/service.d/aiguard.sh
for p in /proc/[0-9]*; do
  cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
  case "$cmd" in
    *aiguard/watchdog.sh*|aiguardd*) kill -9 "${p#/proc/}" 2>/dev/null ;;
  esac
done
if [ -f "$DIR/aiguard.apk" ]; then
  CLASSPATH="$DIR/aiguard.apk" /system/bin/app_process /system/bin com.aiguard.daemon.DaemonMain --teardown
fi
# 兜底：守护进程无法启动时也要拆掉防火墙
for t in iptables ip6tables; do
  for c in AIGUARD_OUT AIGUARD_OUT6; do
    while /system/bin/$t -w -D OUTPUT -j $c 2>/dev/null; do :; done
    /system/bin/$t -w -F $c 2>/dev/null; /system/bin/$t -w -X $c 2>/dev/null
  done
done
while /system/bin/iptables -w -t nat -D OUTPUT -j AIGUARD_DNS 2>/dev/null; do :; done
/system/bin/iptables -w -t nat -F AIGUARD_DNS 2>/dev/null; /system/bin/iptables -w -t nat -X AIGUARD_DNS 2>/dev/null
/system/bin/iptables -w -F AIGUARD_CN 2>/dev/null; /system/bin/iptables -w -X AIGUARD_CN 2>/dev/null
if [ "$1" = "--purge" ]; then
  rm -rf "$DIR"
else
  rm -f "$DIR/aiguard.apk" "$DIR/watchdog.sh" "$DIR/ipc_token" "$DIR/uninstalling"
  rm -rf "$DIR/bin" "$DIR/run"
fi
echo "AIGUARD_UNINSTALL_OK"
