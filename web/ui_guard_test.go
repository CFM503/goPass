package web

import (
	"bytes"
	"os"
	"regexp"
	"testing"
)

// inlineHandlerRe 匹配 HTML 属性位置上的内联事件处理器（onclick="…" 等）。
// 要求前面是空白，避免误伤 textContent= 、btn.disabled= 这类普通赋值。
var inlineHandlerRe = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)

// 内联事件处理器的属性值要经过两道解码：HTML 先把 &#39; 还原成 '，再把整段文本
// 交给 JS 引擎解析。esc() 只做 HTML 层转义，所以放进 onclick="removeProcess('${…}')"
// 之后，进程名里的单引号会逃出字符串字面量——白名单是用户可写的（config.json 同样
// 能直接编辑），于是进程名变成了一段可执行代码。
//
// 2026-09 修的正是这个：renderProcesses 曾用内联 onclick，进程名
// ');window.__xss=1;// 会在点击时执行，Don't Starve.exe 则直接语法错误、按钮报废。
// 改用 data-* 属性 + addEventListener 之后没有第二道解码，属性值就是原文。
//
// 这条测试是护栏，不是证明：它拦住"有人图省事又写回内联处理器"。
func TestUIHasNoInlineEventHandlers(t *testing.T) {
	for _, name := range []string{"index.html", "js/app.js"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		loc := inlineHandlerRe.FindIndex(data)
		if loc == nil {
			continue
		}
		line := 1 + bytes.Count(data[:loc[0]], []byte("\n"))
		end := loc[0] + 60
		if end > len(data) {
			end = len(data)
		}
		t.Errorf("%s:%d 内联事件处理器 %q\n"+
			"属性值会先按 HTML 解码再交给 JS 引擎，esc() 的 &#39; 被还原成 ' 后会逃出字符串字面量。\n"+
			"改用 data-* 属性 + addEventListener。",
			name, line, string(data[loc[0]:end]))
	}
}

// 进程行的删除按钮必须走 data-process，这是上面那条护栏认可的替代写法。
// 断言它存在，是为了让"换了个别的机制"这件事显式地绊住测试，而不是静默通过。
func TestProcessRowsBindThroughDataAttribute(t *testing.T) {
	data, err := os.ReadFile("js/app.js")
	if err != nil {
		t.Fatalf("read js/app.js: %v", err)
	}
	if !bytes.Contains(data, []byte("data-process=")) {
		t.Error("js/app.js 不再用 data-process 绑定进程操作：若改了机制，请重新审视 TestUIHasNoInlineEventHandlers 的约束")
	}
}
