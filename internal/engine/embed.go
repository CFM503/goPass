package engine

import _ "embed"

//go:embed windivert/WinDivert.dll
var windivertDLL []byte

//go:embed windivert/WinDivert64.sys
var windivertSYS []byte
