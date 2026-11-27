// Package version 保存 Windows 版的版本号，构建时用 -ldflags -X 覆盖
package version

// Version 是界面与防护服务共用的版本号；界面据此判断服务是否需要升级
var Version = "1.1.1"
