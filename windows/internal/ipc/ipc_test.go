package ipc

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := WriteLine(&b, []byte(`{"type":"status"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLine(&b)
	if err != nil || string(got) != `{"type":"status"}` {
		t.Fatalf("得到 %q, %v", got, err)
	}
}

func TestLongLineSpansBuffers(t *testing.T) {
	long := strings.Repeat("a", 200<<10)
	got, err := ReadLine(strings.NewReader(long + "\n"))
	if err != nil || len(got) != len(long) {
		t.Fatalf("长度 %d, %v", len(got), err)
	}
}

func TestTooLarge(t *testing.T) {
	_, err := ReadLine(strings.NewReader(strings.Repeat("a", MaxMessage+10) + "\n"))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("应拒绝超大消息，得到 %v", err)
	}
	if WriteLine(&bytes.Buffer{}, make([]byte, MaxMessage+1)) == nil {
		t.Fatal("写入超大消息应报错")
	}
}

func TestRejectsEmbeddedNewline(t *testing.T) {
	if WriteLine(&bytes.Buffer{}, []byte("a\nb")) == nil {
		t.Fatal("内容含换行应报错")
	}
}

func TestEOFWithoutNewline(t *testing.T) {
	got, err := ReadLine(strings.NewReader("abc"))
	if err != nil || string(got) != "abc" {
		t.Fatalf("得到 %q, %v", got, err)
	}
	if _, err := ReadLine(strings.NewReader("")); err == nil {
		t.Fatal("空连接应报错")
	}
}

func TestSDDL(t *testing.T) {
	sd, err := PipeSDDL("S-1-5-21-1004336348-1177238915-682003330-1001")
	if err != nil || !strings.Contains(sd, "(A;;0x12019b;;;S-1-5-21-1004336348-1177238915-682003330-1001)") || !strings.HasPrefix(sd, "D:P(A;;GA;;;SY)(A;;GA;;;BA)") {
		t.Fatalf("得到 %q, %v", sd, err)
	}
	for _, bad := range []string{"", "S-1-5-21-1)(A;;GA;;;WD", "WD", "S-1-1-0"} {
		if _, err := PipeSDDL(bad); err == nil {
			t.Fatalf("%q 应被拒绝", bad)
		}
	}
}
