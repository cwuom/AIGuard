package core

import (
	"slices"
	"strings"
)

// GameReasonManual 是手动开启游戏模式时状态里的原因文字，界面据此区分手动与自动
const GameReasonManual = "手动开启"

// 游戏加速器按安装路径里的关键词识别：它们的进程名各版本经常变，安装目录名稳定得多
var accelerators = []struct{ keyword, name string }{
	{`\netease\uu\`, "UU 加速器"},
	{`\uu加速器\`, "UU 加速器"},
	{`\uubooster\`, "UU 加速器"},
	{"leigod", "雷神加速器"},
	{"雷神加速器", "雷神加速器"},
	{"xunyou", "迅游加速器"},
	{"迅游", "迅游加速器"},
	{"qiyou", "奇游加速器"},
	{"奇游", "奇游加速器"},
	{"biubiu", "biubiu 加速器"},
}

// 游戏库目录：其下第一级目录名就是游戏名
var gameLibraries = []string{`\steamapps\common\`, `\epic games\`, `\wegameapps\`, `\riot games\`, `\hoyoplay\games\`, `\mihoyo launcher\games\`}

// 游戏库里常驻但不是游戏的目录（平台组件、启动器、壁纸、运行库），不能让它们挂着游戏模式
var notGames = []string{"launcher", "riot client", "wallpaper_engine", "wallpaper engine", "steamworks shared", "directx", "_commonredist",
	"rail_apps", "epic online services", "steamvr", "redist", "prerequisites", "support"}

// 游戏目录里的辅助程序：只要游戏本体在跑才算，打开这些不算
var helperWords = []string{"launcher", "helper", "service", "crash", "report", "update", "install", "setup", "unins", "redist",
	"anticheat", "easyanticheat", "battleye", "eac_", "cefsubprocess", "webhelper", "overlay", "bootstrap", "prereq", "vc_redist", "dxsetup"}

// IsGameHelper 判断可执行文件名是不是启动器、服务、崩溃上报、反作弊、安装更新一类的辅助程序
func IsGameHelper(exeBase string) bool {
	b := strings.ToLower(exeBase)
	for _, w := range helperWords {
		if strings.Contains(b, w) {
			return true
		}
	}
	return false
}

var gameExecutables = map[string]string{
	"yuanshen.exe": "原神", "genshinimpact.exe": "原神", "starrail.exe": "崩坏：星穹铁道", "zenlesszonezero.exe": "绝区零",
	"league of legends.exe": "英雄联盟", "cs2.exe": "Counter-Strike 2", "csgo.exe": "CS:GO", "dota2.exe": "Dota 2",
	"tslgame.exe": "PUBG", "overwatch.exe": "守望先锋", "narakabladepoint.exe": "永劫无间", "wow.exe": "魔兽世界",
	"r5apex.exe": "Apex 英雄", "r5apex_dx12.exe": "Apex 英雄", "gta5.exe": "GTA V", "gta5_enhanced.exe": "GTA V",
	"eldenring.exe": "艾尔登法环", "crossfire.exe": "穿越火线", "dnf.exe": "地下城与勇士", "lostark.exe": "失落的方舟",
	"forzahorizon5.exe": "极限竞速：地平线 5", "cod.exe": "使命召唤", "bf2042.exe": "战地 2042",
	"minecraft.windows.exe": "Minecraft", "rocketleague.exe": "火箭联盟", "destiny2.exe": "命运 2",
	"cyberpunk2077.exe": "赛博朋克 2077", "eafc25.exe": "EA FC", "fc25.exe": "EA FC", "wuthering waves.exe": "鸣潮",
}

// DetectGame 判断进程是不是游戏或游戏加速器，返回展示用的名字。
// extra 是用户补充的游戏进程名（已清洗的小写 xxx.exe）
func DetectGame(exePath string, extra []string) (name string, accelerator bool) {
	if exePath == "" {
		return "", false
	}
	lower := strings.ToLower(strings.ReplaceAll(exePath, "/", `\`))
	base := ExeBaseName(exePath)
	for _, a := range accelerators {
		if strings.Contains(lower, a.keyword) {
			return a.name, true
		}
	}
	if slices.Contains(extra, base) {
		return strings.TrimSuffix(base, ".exe"), false
	}
	if n, ok := gameExecutables[base]; ok {
		return n, false
	}
	if IsGameHelper(base) {
		return "", false
	}
	// 虚幻引擎的发行版可执行文件统一叫 Xxx-Win64-Shipping.exe
	if strings.HasSuffix(base, "-win64-shipping.exe") || strings.HasSuffix(base, "-wingdk-shipping.exe") {
		return gameFolder(exePath, lower, strings.TrimSuffix(base[:strings.LastIndex(base, "-win")], "client")), false
	}
	for _, lib := range gameLibraries {
		i := strings.Index(lower, lib)
		if i < 0 {
			continue
		}
		rest := lower[i+len(lib):]
		for _, skip := range notGames {
			if strings.Contains(rest, skip) {
				return "", false
			}
		}
		return gameFolder(exePath, lower, ""), false
	}
	return "", false
}

// gameFolder 优先用游戏库下的目录名当游戏名（保留原始大小写），找不到时用 fallback 或文件名
func gameFolder(exePath, lower, fallback string) string {
	if len(exePath) != len(lower) {
		// 个别字符转小写后字节数会变，这时下标不能套回原串
		exePath = lower
	}
	for _, lib := range gameLibraries {
		if i := strings.Index(lower, lib); i >= 0 {
			rest := exePath[i+len(lib):]
			if j := strings.IndexAny(rest, `\/`); j > 0 {
				return rest[:j]
			}
		}
	}
	if fallback != "" {
		return fallback
	}
	return strings.TrimSuffix(ExeBaseName(exePath), ".exe")
}
