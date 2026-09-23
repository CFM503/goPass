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

// ERROR_ACCESS_DENIED 必须与"已在运行"同等对待：跨完整性级别（普通权限实例
// 访问管理员创建的 Global\ 对象）与缺少 SeCreateGlobalPrivilege 都返回它。
// 把它当成可恢复的普通错误，会让 main 继续启动并随即停掉 WinDivert 服务，
// 打断第一个实例的连接。这里不碰真实 mutex，因此不依赖本机是否已运行 GoPass。
func TestCreateMutexErrorsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"already exists", windows.ERROR_ALREADY_EXISTS, ErrAlreadyRunning},
		{"access denied", windows.ERROR_ACCESS_DENIED, ErrAlreadyRunning},
		{"nil passes through", nil, nil},
		{"other error passes through", windows.ERROR_INVALID_HANDLE, windows.ERROR_INVALID_HANDLE},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyCreateMutexErr(c.err); got != c.want {
				t.Fatalf("classifyCreateMutexErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
