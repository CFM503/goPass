package tray

import (
	"log"
	"syscall"
	"unsafe"
)

const (
	WM_USER         = 0x0400
	WM_COMMAND      = 0x0111
	WM_DESTROY      = 0x0002
	WM_RBUTTONUP    = 0x0205
	WM_LBUTTONUP    = 0x0202
	WM_USER_TRAY    = WM_USER + 1
	NIM_ADD         = 0x00000000
	NIM_DELETE      = 0x00000002
	NIF_MESSAGE     = 0x00000001
	NIF_ICON        = 0x00000002
	NIF_TIP         = 0x00000004
	TPM_RIGHTBUTTON = 0x0002
	TPM_RETURNCMD   = 0x0100
	MF_STRING       = 0x00000000
	MF_SEPARATOR    = 0x00000800
	IDM_OPEN        = 1
	IDM_EXIT        = 2
	CS_HREDRAW      = 0x0002
	CS_VREDRAW      = 0x0001
	IDI_APPLICATION = 32512
	SW_SHOWNORMAL   = 1
)

var (
	shell32             = syscall.NewLazyDLL("shell32.dll")
	user32              = syscall.NewLazyDLL("user32.dll")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")
	procCreatePopupMenu = user32.NewProc("CreatePopupMenu")
	procAppendMenu      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu  = user32.NewProc("TrackPopupMenu")
	procDestroyMenu     = user32.NewProc("DestroyMenu")
	procPostQuitMessage = user32.NewProc("PostQuitMessage")
	procDefWindowProc   = user32.NewProc("DefWindowProcW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procGetCursorPos    = user32.NewProc("GetCursorPos")
	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
	procRegisterClassEx = user32.NewProc("RegisterClassExW")
	procCreateWindowEx  = user32.NewProc("CreateWindowExW")
	procLoadIcon        = user32.NewProc("LoadIconW")
	procGetMessage      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage = user32.NewProc("DispatchMessageW")
	procShellExecute    = shell32.NewProc("ShellExecuteW")
)

type notifyIconData struct {
	CbSize           uint32
	HWnd             syscall.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            syscall.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	BalloonIcon      syscall.Handle
}

type msg struct {
	HWnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      [8]byte
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

var trayWnd syscall.Handle
var iconAdded bool
var hInstance uintptr

func utf16Ptr(s string) *uint16 {
	return syscall.StringToUTF16Ptr(s)
}

func wndProc(hWnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_COMMAND:
		cmd := uint16(wParam)
		if cmd == IDM_EXIT {
			RemoveTray()
			procPostQuitMessage.Call(0)
		} else if cmd == IDM_OPEN {
			openBrowser()
		}
		return 0
	case WM_RBUTTONUP:
		showContextMenu(hWnd)
		return 0
	case WM_LBUTTONUP:
		openBrowser()
		return 0
	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(
		uintptr(hWnd),
		uintptr(msg),
		wParam,
		lParam,
	)
	return ret
}

func showContextMenu(hWnd syscall.Handle) {
	procSetForegroundWindow.Call(uintptr(hWnd))

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	procAppendMenu.Call(hMenu, MF_STRING, IDM_OPEN, uintptr(unsafe.Pointer(utf16Ptr("打开 Web UI"))))
	procAppendMenu.Call(hMenu, MF_SEPARATOR, 0, 0)
	procAppendMenu.Call(hMenu, MF_STRING, IDM_EXIT, uintptr(unsafe.Pointer(utf16Ptr("退出"))))

	type POINT struct{ X, Y int32 }
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		TPM_RIGHTBUTTON|TPM_RETURNCMD,
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		uintptr(hWnd),
		0,
	)

	if cmd == IDM_EXIT {
		RemoveTray()
		procPostQuitMessage.Call(0)
	} else if cmd == IDM_OPEN {
		openBrowser()
	}
}

func openBrowser() {
	procShellExecute.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr("open"))),
		uintptr(unsafe.Pointer(utf16Ptr("http://127.0.0.1:8080"))),
		0,
		0,
		SW_SHOWNORMAL,
	)
}

func loadSysIcon() syscall.Handle {
	hIcon, _, _ := procLoadIcon.Call(0, IDI_APPLICATION)
	return syscall.Handle(hIcon)
}

// Setup creates the system tray icon and runs message loop
func Setup(listenAddr string) {
	hInstance, _, _ = procGetModuleHandle.Call(0)

	className := utf16Ptr("GoPassTray")
	windowName := utf16Ptr("GoPass")

	wc := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		Style:     CS_HREDRAW | CS_VREDRAW,
		WndProc:   syscall.NewCallback(wndProc),
		Instance:  syscall.Handle(hInstance),
		Icon:      loadSysIcon(),
		ClassName: className,
	}

	atom, _, _ := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		log.Printf("[Tray] 注册窗口类失败")
		return
	}

	hWnd, _, _ := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0,
		0, 0, 300, 200,
		0, 0, hInstance, 0,
	)
	if hWnd == 0 {
		log.Printf("[Tray] 创建窗口失败")
		return
	}
	trayWnd = syscall.Handle(hWnd)

	hIcon := loadSysIcon()
	tipStr := "GoPass v1.3.1\n点击打开 Web UI"
	tipUTF16, _ := syscall.UTF16FromString(tipStr)
	nid := notifyIconData{
		CbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:             trayWnd,
		UID:              1,
		UFlags:           NIF_MESSAGE | NIF_ICON | NIF_TIP,
		UCallbackMessage: WM_USER_TRAY,
		HIcon:            hIcon,
	}
	copy(nid.SzTip[:], tipUTF16)

	ret, _, err := procShellNotifyIcon.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		log.Printf("[Tray] 添加托盘图标失败: %v", err)
		return
	}
	iconAdded = true

	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if ret == 0 || ret == ^uintptr(0) {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// RemoveTray removes the system tray icon
func RemoveTray() {
	if !iconAdded {
		return
	}
	nid := notifyIconData{
		CbSize: uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:   trayWnd,
		UID:    1,
	}
	procShellNotifyIcon.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
	iconAdded = false
}
