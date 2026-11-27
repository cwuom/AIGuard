package core

import "testing"

func TestDetectGame(t *testing.T) {
	cases := []struct {
		path, name string
		acc        bool
	}{
		{`C:\Program Files (x86)\Netease\UU\uu.exe`, "UU 加速器", true},
		{`D:\LeiGod\leigod_launcher.exe`, "雷神加速器", true},
		{`C:\Program Files\Xunyou\xunyou.exe`, "迅游加速器", true},
		{`D:\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe`, "Counter-Strike 2", false},
		{`D:\Steam\steamapps\common\Black Myth Wukong\b1\Binaries\Win64\b1-Win64-Shipping.exe`, "Black Myth Wukong", false},
		{`E:\Games\Delta Force\DeltaForceClient-Win64-Shipping.exe`, "deltaforce", false},
		{`D:\Steam\steamapps\common\Hades\x64\Hades.exe`, "Hades", false},
		{`C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe`, "Fortnite", false},
		{`D:\WeGameApps\英雄联盟\Game\League of Legends.exe`, "英雄联盟", false},
		{`C:\Program Files\HoYoPlay\games\Genshin Impact Game\YuanShen.exe`, "原神", false},
		// 启动器、壁纸、运行库都不算游戏
		{`C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe`, "", false},
		{`D:\Steam\steamapps\common\wallpaper_engine\wallpaper32.exe`, "", false},
		{`C:\Riot Games\Riot Client\RiotClientServices.exe`, "", false},
		{`C:\Program Files (x86)\Steam\steam.exe`, "", false},
		{`C:\Program Files\Netease\UURemote\uuremote.exe`, "", false},
		// 平台组件与游戏目录里的辅助程序：打开它们不算在玩游戏
		{`C:\Program Files (x86)\Epic Games\Epic Online Services\EpicOnlineServicesUserHelper.exe`, "", false},
		{`C:\Program Files (x86)\Epic Games\Epic Online Services\service\EpicOnlineServices.exe`, "", false},
		{`D:\Steam\steamapps\common\Game\EasyAntiCheat\EasyAntiCheat_EOS_Setup.exe`, "", false},
		{`D:\Steam\steamapps\common\Game\Engine\Binaries\Win64\CrashReportClient.exe`, "", false},
		{`D:\Steam\steamapps\common\Game\UnityCrashHandler64.exe`, "", false},
		{`D:\Steam\steamapps\common\SteamVR\bin\win64\vrserver.exe`, "", false},
		{`C:\Riot Games\VALORANT\live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe`, "VALORANT", false},
		{`D:\WeGameApps\英雄联盟\TCLS\Client.exe`, "英雄联盟", false},
		{`C:\Program Files\Google\Chrome\Application\chrome.exe`, "", false},
		{"", "", false},
	}
	for _, c := range cases {
		name, acc := DetectGame(c.path, nil)
		if name != c.name || acc != c.acc {
			t.Errorf("%s：得到 %q/%v，期望 %q/%v", c.path, name, acc, c.name, c.acc)
		}
	}
	if name, _ := DetectGame(`C:\Games\MyGame\mygame.exe`, []string{"mygame.exe"}); name != "mygame" {
		t.Fatalf("自定义游戏进程没识别：%q", name)
	}
}
