#!/bin/zsh
# 卸载 AIGuard 守护进程并撤销防火墙规则。加 --purge 同时删除设置和订阅
set -euo pipefail
LABEL="com.aiguard.daemon"
[[ $EUID -eq 0 ]] || { echo "请用 sudo 运行" >&2; exit 1; }

# 升级保持标记会让守护进程退出时保留断网规则，卸载必须先清掉
rm -f "/Library/Application Support/AIGuard/upgrade-hold"
launchctl bootout "system/$LABEL" 2>/dev/null || true
sleep 1
# 守护进程正常退出时会自己清理，这里兜底
/sbin/pfctl -a "com.apple/250.AIGuard" -F all 2>/dev/null || true
/sbin/pfctl -a "com.apple/240.AIGuardUS" -F all 2>/dev/null || true
pkill -f "/Library/PrivilegedHelperTools/$LABEL/mihomo" 2>/dev/null || true
# 守护进程正常退出会恢复系统 IPv6；崩溃过的话按备份兜底恢复
BACKUP="/Library/Application Support/AIGuard/ipv6-backup.tsv"
# 恢复失败的条目写回备份（例如网卡暂时不在），不能连同备份一起删掉；--purge 也要保留
RESTORE_FAILED=0
restore_backup() {
  local file="$1" kind="$2" left="" svc value
  while IFS=$'\t' read -r svc value; do
    [[ -n "$svc" ]] || continue
    if ! "${@:3}" "$svc" "$value"; then left+="$svc"$'\t'"$value"$'\n'; fi
  done < "$file"
  if [[ -z "$left" ]]; then
    rm -f "$file"
    echo "已恢复系统 $kind 设置"
  else
    printf '%s' "$left" > "$file.tmp" && mv -f "$file.tmp" "$file"
    RESTORE_FAILED=1
    echo "⚠️ 部分网络服务的 $kind 没能恢复，备份保留在 $file：" >&2
    printf '%s' "$left" | cut -f1 >&2
  fi
}
restore_ipv6() {
  case "$2" in
    Automatic) networksetup -setv6automatic "$1" >/dev/null 2>&1 ;;
    LinkLocal) networksetup -setv6LinkLocal "$1" >/dev/null 2>&1 ;;
    *) true ;;
  esac
}
restore_dns() { networksetup -setdnsservers "$1" ${=2} >/dev/null 2>&1; }
if [[ -f "$BACKUP" ]]; then
  restore_backup "$BACKUP" IPv6 restore_ipv6
fi
rm -f "/Library/LaunchDaemons/$LABEL.plist" "/var/run/$LABEL.sock"
rm -rf "/Library/PrivilegedHelperTools/$LABEL"
DNS_BACKUP="/Library/Application Support/AIGuard/dns-backup.tsv"
if [[ -f "$DNS_BACKUP" ]]; then
  restore_backup "$DNS_BACKUP" DNS restore_dns
fi
if [[ "${1:-}" == "--purge" ]]; then
  SUPPORT="/Library/Application Support/AIGuard"
  if (( RESTORE_FAILED )); then
    # 只删其余数据，没恢复的系统网络备份留着，下次卸载或手动恢复时还能用
    [[ -d "$SUPPORT" ]] && find "$SUPPORT" -mindepth 1 -maxdepth 1 ! -name dns-backup.tsv ! -name ipv6-backup.tsv -exec rm -rf {} +
    echo "已删除设置、订阅与日志（保留了未恢复的网络备份）"
  else
    rm -rf "$SUPPORT"
    echo "已删除设置、订阅与日志"
  fi
  rm -rf /Library/Logs/AIGuard
fi
echo "✅ 已卸载守护进程（App 本体请手动移到废纸篓）"
