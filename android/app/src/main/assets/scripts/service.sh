#!/system/bin/sh
# AIGuard：KernelSU / Magisk 开机脚本（/data/adb/service.d/aiguard.sh），只负责拉起看门狗
DIR=/data/adb/aiguard
[ -f "$DIR/aiguard.apk" ] || exit 0
[ -f "$DIR/uninstalling" ] && exit 0
setsid /system/bin/sh "$DIR/watchdog.sh" </dev/null >/dev/null 2>&1 &
