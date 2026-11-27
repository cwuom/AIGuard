// Package ipc 是界面与守护服务之间的传输层：一次连接一问一答，各一行 JSON。
// 编解码由调用方用 core 的 Envelope/Response 完成，这里只负责分帧和大小上限。
package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// MaxMessage 与 core.MaxMessageBytes 一致：事件列表与设置最大也远小于它
const MaxMessage = 4 << 20

var ErrTooLarge = errors.New("消息超过 4 MiB 上限")

// ReadLine 读取一行（不含换行），超过上限直接报错，避免恶意客户端撑爆内存
func ReadLine(r io.Reader) ([]byte, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var buf bytes.Buffer
	for {
		chunk, err := br.ReadSlice('\n')
		buf.Write(chunk)
		if buf.Len() > MaxMessage {
			return nil, ErrTooLarge
		}
		if err == nil {
			return bytes.TrimRight(buf.Bytes(), "\r\n"), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && buf.Len() > 0 {
			return buf.Bytes(), nil
		}
		return nil, err
	}
}

// WriteLine 写一行 JSON；内容里不应出现换行（encoding/json 默认不会输出原始换行）
func WriteLine(w io.Writer, b []byte) error {
	if len(b) > MaxMessage {
		return ErrTooLarge
	}
	if bytes.IndexByte(b, '\n') >= 0 {
		return errors.New("消息里不能有换行")
	}
	_, err := w.Write(append(b, '\n'))
	return err
}
