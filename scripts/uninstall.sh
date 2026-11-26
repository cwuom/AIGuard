#!/bin/zsh
# 卸载 AIGuard 守护进程并撤销防火墙规则。加 --purge 同时删除设置和订阅
set -euo pipefail
LABEL="com.aiguard.daemon"
[[ $EUID -eq 0 ]] || { echo "请用 sudo 运行" >&2; exit 1; }

launchctl bootout "system/$LABEL" 2>/dev/null || true
sleep 1
# 守护进程正常退出时会自己清理，这里兜底
/sbin/pfctl -a "com.apple/250.AIGuard" -F all 2>/dev/null || true
/sbin/pfctl -a "com.apple/240.AIGuardUS" -F all 2>/dev/null || true
pkill -f "/Library/PrivilegedHelperTools/$LABEL/mihomo" 2>/dev/null || true
# 守护进程正常退出会恢复系统 IPv6；崩溃过的话按备份兜底恢复
BACKUP="/Library/Application Support/AIGuard/ipv6-backup.tsv"
if [[ -f "$BACKUP" ]]; then
  while IFS=$'\t' read -r svc mode; do
    case "$mode" in
      Automatic) networksetup -setv6automatic "$svc" 2>/dev/null || true ;;
      LinkLocal) networksetup -setv6LinkLocal "$svc" 2>/dev/null || true ;;
    esac
  done < "$BACKUP"
  rm -f "$BACKUP"
  echo "已恢复系统 IPv6 设置"
fi
rm -f "/Library/LaunchDaemons/$LABEL.plist" "/var/run/$LABEL.sock"
rm -rf "/Library/PrivilegedHelperTools/$LABEL"
DNS_BACKUP="/Library/Application Support/AIGuard/dns-backup.tsv"
if [[ -f "$DNS_BACKUP" ]]; then
  while IFS=$'\t' read -r svc servers; do
    [[ -n "$svc" ]] || continue
    networksetup -setdnsservers "$svc" ${=servers} 2>/dev/null || true
  done < "$DNS_BACKUP"
  rm -f "$DNS_BACKUP"
  echo "已恢复系统 DNS 设置"
fi
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "/Library/Application Support/AIGuard" /Library/Logs/AIGuard
  echo "已删除设置、订阅与日志"
fi
echo "✅ 已卸载守护进程（App 本体请手动移到废纸篓）"
