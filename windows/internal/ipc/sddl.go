package ipc

import (
	"fmt"
	"regexp"
)

// 只接受普通本地/域用户 SID（S-1-5-21-…）；Everyone、匿名等公共 SID 一律拒绝
var userSID = regexp.MustCompile(`^S-1-5-21(-[0-9]{1,10}){3,5}$`)

// PipeSDDL 生成管道的安全描述符：SYSTEM 与管理员完全控制，安装界面的那个用户可读写，其他人连不上。
// 没有显式的 Everyone/Authenticated Users，所以同机的其他账户无法控制守护服务
func PipeSDDL(sid string) (string, error) {
	if !userSID.MatchString(sid) {
		return "", fmt.Errorf("非法用户 SID：%q", sid)
	}
	// 0x12019b = FILE_GENERIC_READ | FILE_GENERIC_WRITE 去掉 FILE_CREATE_PIPE_INSTANCE（0x4）：
	// 界面能读写，但不能自己再开一个同名管道实例去冒充服务
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;" + sid + ")", nil
}

// ValidUserSID 供安装参数校验使用
func ValidUserSID(sid string) bool { return userSID.MatchString(sid) }
