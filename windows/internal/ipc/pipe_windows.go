//go:build windows

package ipc

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Handler 处理一条请求并返回一行响应
type Handler func(ctx context.Context, req []byte) []byte

// Server 在命名管道上服务界面请求
type Server struct {
	ln net.Listener
	// AllowedExe 是允许连接的界面程序路径（不区分大小写）；管道 DACL 之外再校验一次客户端进程
	AllowedExe []string
	Handler    Handler
}

// Listen 创建管道；userSID 是安装时记录的界面用户
func Listen(name, userSID string) (*Server, error) {
	sd, err := PipeSDDL(userSID)
	if err != nil {
		return nil, err
	}
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sd, InputBufferSize: 64 << 10, OutputBufferSize: 64 << 10})
	if err != nil {
		return nil, err
	}
	return &Server{ln: ln}, nil
}

func (s *Server) Close() error { return s.ln.Close() }

// Serve 阻塞直到 Close；每个连接一个 goroutine，处理顺序由 Handler 自己保证
func (s *Server) Serve(ctx context.Context) error {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, winio.ErrPipeListenerClosed) {
				return nil
			}
			continue
		}
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(90 * time.Second))
	if !s.clientAllowed(c) {
		WriteLine(c, []byte(`{"ok":false,"error":"拒绝连接：客户端不是 AIGuard 界面"}`))
		return
	}
	req, err := ReadLine(c)
	if err != nil {
		return
	}
	WriteLine(c, s.Handler(ctx, req))
}

func (s *Server) clientAllowed(c net.Conn) bool {
	if len(s.AllowedExe) == 0 {
		return true
	}
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(f.Fd()), &pid); err != nil {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return false
	}
	exe := windows.UTF16ToString(buf[:n])
	for _, a := range s.AllowedExe {
		if strings.EqualFold(a, exe) {
			return true
		}
	}
	return false
}

// ErrUntrustedServer 表示管道对面不是期望的服务进程（可能有程序抢先占了管道名）
var ErrUntrustedServer = errors.New("管道对端不是防护服务")

// Call 连接服务、发送一行请求并读取一行响应。serverPID 非 nil 时先核对管道对端进程号
func Call(ctx context.Context, name string, req []byte, serverPID func() uint32) ([]byte, error) {
	c, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if serverPID != nil {
		f, ok := c.(interface{ Fd() uintptr })
		var pid uint32
		if !ok || windows.GetNamedPipeServerProcessId(windows.Handle(f.Fd()), &pid) != nil {
			return nil, ErrUntrustedServer
		}
		if want := serverPID(); want == 0 || want != pid {
			return nil, ErrUntrustedServer
		}
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := WriteLine(c, req); err != nil {
		return nil, err
	}
	return ReadLine(c)
}
