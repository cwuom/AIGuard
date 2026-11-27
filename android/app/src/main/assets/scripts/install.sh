#!/system/bin/sh
# AIGuard 守护进程安装/升级（由 App 通过 su 调用）：install.sh <APK 路径> <App uid> <暂存目录>
set -e
APK="$1"
APP_UID="$2"
STAGE="$3"
DIR=/data/adb/aiguard

case "$APK" in
  /data/app/*.apk) ;;
  *) echo "APK 路径异常：$APK"; exit 2 ;;
esac
case "$APP_UID" in
  ''|*[!0-9]*) echo "uid 异常：$APP_UID"; exit 2 ;;
esac
[ -f "$STAGE/token" ] || { echo "缺少 token"; exit 2; }
[ -d /data/adb/service.d ] || mkdir -p /data/adb/service.d

umask 077
mkdir -p "$DIR/run" "$DIR/logs"
rm -f "$DIR/uninstalling"
cp -f "$APK" "$DIR/aiguard.apk.new"
mv -f "$DIR/aiguard.apk.new" "$DIR/aiguard.apk"
cp -f "$STAGE/watchdog.sh" "$DIR/watchdog.sh"
cp -f "$STAGE/uninstall.sh" "$DIR/uninstall.sh"
cp -f "$STAGE/token" "$DIR/ipc_token"
echo "$APP_UID" > "$DIR/app_uid"
chmod 700 "$DIR" "$DIR/watchdog.sh" "$DIR/uninstall.sh"
chmod 600 "$DIR/aiguard.apk" "$DIR/ipc_token" "$DIR/app_uid"
cp -f "$STAGE/service.sh" /data/adb/service.d/aiguard.sh
chmod 755 /data/adb/service.d/aiguard.sh

# 结束旧守护进程，看门狗会用新 APK 重新拉起；防火墙规则在交接期间一直生效
for p in /proc/[0-9]*; do
  if grep -q "^aiguardd" "$p/cmdline" 2>/dev/null; then kill -9 "${p#/proc/}" 2>/dev/null || true; fi
done
setsid /system/bin/sh "$DIR/watchdog.sh" </dev/null >/dev/null 2>&1 &
rm -f "$STAGE/token"
echo "AIGUARD_INSTALL_OK"
