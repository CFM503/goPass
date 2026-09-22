package singleton

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAcquireDetectsSecondInstance(t *testing.T) {
	h, err := acquire()
	if errors.Is(err, ErrAlreadyRunning) {
		t.Skip("本机已有 GoPass 实例在运行")
	}
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer windows.CloseHandle(h)

	// 对象仍存在（句柄未关）→ 第二次必须报"已在运行"
	if _, err := acquire(); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second acquire = %v, want ErrAlreadyRunning", err)
	}

	// 句柄关闭后对象消失，可以再次创建（确保没有残留影响其它测试）
	_ = windows.CloseHandle(h)
	if h2, err := acquire(); err != nil {
		t.Fatalf("acquire after release: %v", err)
	} else {
		defer windows.CloseHandle(h2)
	}
}

func TestAcquireIsIdempotent(t *testing.T) {
	if err := Acquire(); errors.Is(err, ErrAlreadyRunning) {
		t.Skip("本机已有 GoPass 实例在运行")
	} else if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := Acquire(); err != nil {
		t.Fatalf("repeat Acquire should be a no-op: %v", err)
	}
}
