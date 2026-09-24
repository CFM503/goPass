package engine

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/CFM503/goPass/internal/process"
	"golang.org/x/sys/windows"
)

const (
	layerNetwork = 0
	priorityDefault = 0
	flagOutbound = 1 << 17
	flagLoopback = 1 << 18
)

// winDivertAddress 必须与 WinDivert 2.2 的 WINDIVERT_ADDRESS 严格等长（80 字节）：
// 8(Timestamp) + 8(位域字) + 64(union)。批量收包按 sizeof 切分地址数组，
// 结构体差 4 字节就会把后续地址全部串位，所以 Data 只能是 56 字节。
type winDivertAddress struct { Timestamp int64; Bits uint32; Reserved2 uint32; IfIdx uint32; SubIfIdx uint32; Data [56]byte }
type winDivertDLL struct { dll *windows.DLL; procOpen *windows.Proc; procRecv *windows.Proc; procRecvEx *windows.Proc; procSend *windows.Proc; procSendEx *windows.Proc; procClose *windows.Proc; procCalcChecks *windows.Proc }
var ( wdOnce sync.Once; wdDLL *winDivertDLL; wdErr error )

func stopAndRemoveService(name string) {
	scm, err := windows.OpenSCManager(nil,nil,windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE); if err!=nil{return}; defer windows.CloseServiceHandle(scm)
	svc, err := windows.OpenService(scm,syscall.StringToUTF16Ptr(name),windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS|windows.DELETE); if err!=nil{return}
	var status windows.SERVICE_STATUS; _=windows.ControlService(svc,windows.SERVICE_CONTROL_STOP,&status)
	for i:=0;i<50;i++ { time.Sleep(100*time.Millisecond); if err:=windows.QueryServiceStatus(svc,&status); err!=nil||status.CurrentState==windows.SERVICE_STOPPED{break} }
	_=windows.DeleteService(svc); windows.CloseServiceHandle(svc)
	for i:=0;i<30;i++ { checkSvc,e:=windows.OpenService(scm,syscall.StringToUTF16Ptr(name),windows.SERVICE_QUERY_STATUS); if e!=nil{break}; windows.CloseServiceHandle(checkSvc); time.Sleep(500*time.Millisecond) }
}
func stopAndRemoveWinDivertDriver(){stopAndRemoveService("WinDivert");stopAndRemoveService("WinDivert14")}
func CleanUpDependencies(){stopAndRemoveWinDivertDriver();cwd,err:=os.Getwd();if err!=nil{cwd="."};for _,n:=range []string{"WinDivert.dll","WinDivert64.sys","WinDivert64.sys.tmp"}{_=os.Remove(filepath.Join(cwd,n))}}
func CleanUpOnShutdown(){if wdDLL!=nil&&wdDLL.dll!=nil{_=wdDLL.dll.Release();wdDLL=nil};stopAndRemoveWinDivertDriver();if cwd,err:=os.Getwd();err==nil{for _,n:=range []string{"WinDivert.dll","WinDivert64.sys","WinDivert64.sys.tmp"}{_=os.Remove(filepath.Join(cwd,n))}}}
func fileContentMatch(path string,want []byte)bool{data,err:=os.ReadFile(path);if err!=nil{return false};if len(data)!=len(want){return false};for i:=range data{if data[i]!=want[i]{return false}};return true}
func extractSysFile(path string,data []byte)error{if err:=os.WriteFile(path,data,0755);err==nil{return nil};tmp:=path+".tmp";if err:=os.WriteFile(tmp,data,0755);err!=nil{return err};k:=syscall.NewLazyDLL("kernel32.dll");m:=k.NewProc("MoveFileExW");s,_:=syscall.UTF16PtrFromString(tmp);d,_:=syscall.UTF16PtrFromString(path);ret,_,err:=m.Call(uintptr(unsafe.Pointer(s)),uintptr(unsafe.Pointer(d)),3);if ret!=0{return nil};_=os.Remove(tmp);return fmt.Errorf("replace SYS failed: %w",err)}
func loadWinDivert()(*winDivertDLL,error){wdOnce.Do(func(){stopAndRemoveWinDivertDriver();cwd,err:=os.Getwd();if err!=nil{cwd="."};dllPath:=filepath.Join(cwd,"WinDivert.dll");sysPath:=filepath.Join(cwd,"WinDivert64.sys");if !fileContentMatch(dllPath,windivertDLL){if err:=os.WriteFile(dllPath,windivertDLL,0755);err!=nil{wdErr=err;return}};if !fileContentMatch(sysPath,windivertSYS){if err:=extractSysFile(sysPath,windivertSYS);err!=nil&&!fileContentMatch(sysPath,windivertSYS){wdErr=err;return}};dll,err:=windows.LoadDLL(dllPath);if err!=nil{wdErr=err;return};find:=func(n string)*windows.Proc{p,e:=dll.FindProc(n);if e!=nil{wdErr=e;return nil};return p};findOpt:=func(n string)*windows.Proc{p,e:=dll.FindProc(n);if e!=nil{return nil};return p};wdDLL=&winDivertDLL{dll:dll,procOpen:find("WinDivertOpen"),procRecv:find("WinDivertRecv"),procRecvEx:findOpt("WinDivertRecvEx"),procSend:find("WinDivertSend"),procSendEx:findOpt("WinDivertSendEx"),procClose:find("WinDivertClose"),procCalcChecks:find("WinDivertHelperCalcChecksums")}});return wdDLL,wdErr}
type winDivertHandle struct{handle windows.Handle;dll *winDivertDLL}
func wdOpen(filter string,layer,priority int,flags uint64)(*winDivertHandle,error){dll,err:=loadWinDivert();if err!=nil{return nil,err};p,err:=syscall.BytePtrFromString(filter);if err!=nil{return nil,err};ret,_,eno:=dll.procOpen.Call(uintptr(unsafe.Pointer(p)),uintptr(layer),uintptr(priority),uintptr(flags));if ret==uintptr(windows.InvalidHandle){return nil,fmt.Errorf("WinDivertOpen failed: %w",eno)};return &winDivertHandle{handle:windows.Handle(ret),dll:dll},nil}
func(h *winDivertHandle)Recv(buf []byte)(int,*winDivertAddress,error){if len(buf)==0{return 0,nil,fmt.Errorf("empty receive buffer")};var addr winDivertAddress;var n uint32;ret,_,eno:=h.dll.procRecv.Call(uintptr(h.handle),uintptr(unsafe.Pointer(&buf[0])),uintptr(len(buf)),uintptr(unsafe.Pointer(&n)),uintptr(unsafe.Pointer(&addr)));if ret==0{return 0,nil,fmt.Errorf("WinDivertRecv: %w",eno)};return int(n),&addr,nil}
func(h *winDivertHandle)Send(pkt []byte,addr *winDivertAddress)error{if len(pkt)==0{return fmt.Errorf("empty packet")};var n uint32;ret,_,eno:=h.dll.procSend.Call(uintptr(h.handle),uintptr(unsafe.Pointer(&pkt[0])),uintptr(len(pkt)),uintptr(unsafe.Pointer(&n)),uintptr(unsafe.Pointer(addr)));if ret==0{return fmt.Errorf("WinDivertSend: %w",eno)};return nil}
func(h *winDivertHandle)CalcChecksums(pkt []byte,addr *winDivertAddress)error{if len(pkt)==0{return fmt.Errorf("empty packet")};ret,_,eno:=h.dll.procCalcChecks.Call(uintptr(unsafe.Pointer(&pkt[0])),uintptr(len(pkt)),uintptr(unsafe.Pointer(addr)),0);if ret==0{return fmt.Errorf("WinDivertHelperCalcChecksums: %w",eno)};return nil}
func(h *winDivertHandle)Close(){if h!=nil&&h.handle!=windows.InvalidHandle{_,_,_=h.dll.procClose.Call(uintptr(h.handle));h.handle=windows.InvalidHandle}}
func isProcessElevated()bool{var token windows.Token;if err:=windows.OpenProcessToken(windows.CurrentProcess(),windows.TOKEN_QUERY,&token);err!=nil{return false};defer token.Close();return token.IsElevated()}

// 拦截器运行状态：stopped / running / error（供 /api/status 如实上报）
const (
	stateStopped = "stopped"
	stateRunning = "running"
	stateError   = "error"
)

type Interceptor struct{ handle *winDivertHandle;mu sync.RWMutex;tracker *ConnTracker;proxyIP string;proxyPort uint16;proxy4 [4]byte;proxy4ok bool;tproxyPort uint16;stopCh chan struct{};closeOnce sync.Once;resolver *process.Resolver;whitelist map[string]struct{};policies *flowPolicies;lookupName func(process.Flow) (string, bool);state atomic.Value;stateMsg atomic.Value;lastLookupFailLog time.Time }
func NewInterceptor(tracker *ConnTracker,proxyIP string,proxyPort,tproxyPort uint16,whitelist []string)*Interceptor{
	i:=&Interceptor{tracker:tracker,tproxyPort:tproxyPort,stopCh:make(chan struct{}),resolver:process.NewResolver(),whitelist:make(map[string]struct{}),policies:newFlowPolicies(tracker)}
	// 顺带缓存 proxyIP 的 4 字节形式：热路径每包都要比对目的地址，
	// net.ParseIP 会产生堆分配，不能留在逐包路径上。
	i.SetProxyAddr(proxyIP, proxyPort)
	i.state.Store(stateStopped);i.stateMsg.Store("")
	i.SetWhitelist(whitelist)
	// 进程识别封装成可注入函数，便于对决策逻辑做单测。
	i.lookupName = func(f process.Flow) (string, bool) {
		e, ok := i.resolver.LookupWithRefresh(f)
		if !ok || e.Name == "" { return "", false }
		return e.Name, true
	}
	return i
}

// State 返回拦截器状态与附加信息（错误详情）。
func (i *Interceptor) State() (string, string) {
	st, _ := i.state.Load().(string)
	msg, _ := i.stateMsg.Load().(string)
	return st, msg
}
func (i *Interceptor) setState(st, msg string) { i.state.Store(st); i.stateMsg.Store(msg) }

// decideNewFlow 在连接起点做一次路由决定；该结果之后不再改变。
//   - 没看到连接起点 → 确定放行（绝不中途劫持/阻断已有连接）
//   - 识别不到进程   → policyUndecided：暂按放行，握手期间的下一个 SYN 允许重试
//   - 白名单进程     → 劫持(v4) / 阻断(v6)
//   - 非白名单进程   → 确定放行
func (i *Interceptor) decideNewFlow(isStart bool, lookup func() (string, bool)) policyKind {
	if !isStart { return policyPass }
	name, ok := lookup()
	if !ok {
		if since := time.Since(i.lastLookupFailLog); since > time.Second {
			i.lastLookupFailLog = time.Now()
			log.Printf("[WinDivert] 新连接暂无法识别进程，本次按直连处理（握手期间会重试）")
		}
		return policyUndecided
	}
	if i.isWhitelisted(name) { return policyIntercept }
	return policyPass
}
func(i *Interceptor)SetWhitelist(list []string){m:=make(map[string]struct{},len(list));for _,name:=range list{name=strings.TrimSpace(strings.ToLower(name));if name!=""{m[name]=struct{}{}}};i.mu.Lock();i.whitelist=m;i.mu.Unlock()}
func(i *Interceptor)GetWhitelist()[]string{i.mu.RLock();out:=make([]string,0,len(i.whitelist));for n:=range i.whitelist{out=append(out,n)};i.mu.RUnlock();return out}
func(i *Interceptor)SetProxyAddr(ip string,port uint16){i.mu.Lock();i.proxyIP,i.proxyPort=ip,port;i.proxy4,i.proxy4ok=parseIPv4Bytes(ip);i.mu.Unlock()}

// parseIPv4Bytes 把配置里的上游地址解析成可直接按字节比对的形式。
// 无法解析（空串/主机名/纯 IPv6）时返回 false，表示"不做上游地址豁免"，
// 与旧逻辑 pip == nil 时不豁免的行为一致。
func parseIPv4Bytes(s string) ([4]byte, bool) {
	if s == "" { return [4]byte{}, false }
	v := net.ParseIP(s)
	if v == nil { return [4]byte{}, false }
	v4 := v.To4()
	if v4 == nil { return [4]byte{}, false }
	return [4]byte{v4[0], v4[1], v4[2], v4[3]}, true
}

// Keep one Network-layer WinDivert handle. WinDivert handles at the same
// priority must not overlap; QUIC/IPv6 filtering therefore lives in this
// primary handle instead of separate UDP/IPv6 blockers.
func(i *Interceptor)buildFilter()string{i.mu.RLock();proxyIP:=i.proxyIP;tproxyPort:=i.tproxyPort;i.mu.RUnlock();tcp:="(outbound and ip and tcp and ip.DstAddr != 127.0.0.1";if pip:=net.ParseIP(proxyIP);pip!=nil&&pip.To4()!=nil&&!pip.IsLoopback(){tcp+=fmt.Sprintf(" and ip.DstAddr != %s",pip.To4().String())};tcp+=")";quic:="(outbound and ip and udp and udp.DstPort == 443 and ip.DstAddr != 127.0.0.1";if pip:=net.ParseIP(proxyIP);pip!=nil&&pip.To4()!=nil&&!pip.IsLoopback(){quic+=fmt.Sprintf(" and ip.DstAddr != %s",pip.To4().String())};quic+=")";return fmt.Sprintf("%s or %s or (outbound and ipv6) or (outbound and ip and tcp and tcp.SrcPort == %d)",tcp,quic,tproxyPort)}
func(i *Interceptor)preflight()error{if !isProcessElevated(){return fmt.Errorf("需要管理员权限：请右键 GoPass.exe 选择“以管理员身份运行”")};h,err:=wdOpen(i.buildFilter(),layerNetwork,priorityDefault,0);if err!=nil{return fmt.Errorf("WinDivert 初始化/驱动加载失败：%w",err)};h.Close();return nil}
// Start 是收包主循环：批量收一批包 → 切分 → 逐包决策 → 批量回注。
// 批量收/发由 WinDivert 2.x 的 batched I/O 提供，把"每包两次内核上下文切换"
// 降为"每批各一次"；任何一步异常都只影响当批，状态上报保持原语义。
func (i *Interceptor) Start() error {
	h, err := wdOpen(i.buildFilter(), layerNetwork, priorityDefault, 0)
	if err != nil {
		i.setState(stateError, err.Error())
		return fmt.Errorf("WinDivert 启动失败：%w", err)
	}
	i.mu.Lock()
	i.handle = h
	i.mu.Unlock()
	i.setState(stateRunning, "")
	_ = i.resolver.Refresh()
	process.RefreshIPv6TCP()
	process.RefreshIPv6UDP()
	log.Println("[WinDivert] unified TCP/QUIC/IPv6 interception ready")
	go i.refreshLoop()

	recvBuf := make([]byte, recvBufSize)
	addrs := make([]winDivertAddress, batchPackets)
	q := newSendQueue()
	fails, errored := 0, false
	for {
		select {
		case <-i.stopCh:
			i.flushQueue(q)
			i.setState(stateStopped, "")
			return nil
		default:
		}
		i.mu.RLock()
		h = i.handle
		i.mu.RUnlock()
		if h == nil {
			i.setState(stateStopped, "")
			return nil
		}
		nBytes, nPkts, err := h.RecvBatch(recvBuf, addrs)
		if err != nil {
			select {
			case <-i.stopCh:
				i.setState(stateStopped, "")
				return nil
			default:
			}
			fails++
			if fails >= 20 && !errored {
				msg := fmt.Sprintf("WinDivert 收包持续失败: %v", err)
				i.setState(stateError, msg)
				errored = true
				log.Printf("[WinDivert] %s", msg)
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		fails = 0
		if errored {
			i.setState(stateRunning, "")
			errored = false
		}
		if nBytes > 0 && nPkts > 0 {
			if werr := i.processBatch(recvBuf[:nBytes], addrs[:nPkts], q); werr != nil {
				logRateLimited(werr)
			}
			// 无论本批切分是否出错，已入队的包都要回注，否则会凭空丢包。
			i.flushQueue(q)
		}
	}
}

// processBatch 把一批无间隙拼接的包按 IP 头里的长度字段切开并逐个处理。
// WinDivert 批量模式不返回每个包的长度，只能靠头字段走；
// 长度对不上说明缓冲区解析已不可信，立即报错停止解析本批（已入队的照常回注）。
func (i *Interceptor) processBatch(buf []byte, addrs []winDivertAddress, q *sendQueue) error {
	off, p := 0, 0
	for ; p < len(addrs) && off < len(buf); p++ {
		n, err := packetLen(buf[off:])
		if err != nil {
			return fmt.Errorf("批量收包第 %d 个无法切分(offset=%d/%d): %w", p, off, len(buf), err)
		}
		if off+n > len(buf) {
			return fmt.Errorf("批量收包第 %d 个越界(offset=%d n=%d 总长=%d)", p, off, n, len(buf))
		}
		i.handlePacket(q, buf[off:off+n], &addrs[p])
		off += n
	}
	if off != len(buf) {
		return fmt.Errorf("批量收包长度不一致: %d 个地址只解释了 %d/%d 字节", len(addrs), off, len(buf))
	}
	// 驱动回报的地址数必须与能切出的包数一致；少一个都说明缓冲区解析不可信。
	if p != len(addrs) {
		return fmt.Errorf("批量收包长度不一致: %d 个地址只解释出 %d 个包", len(addrs), p)
	}
	return nil
}

// logErr 限流日志：收包路径上的异常可能逐包出现，不能把日志刷爆。
// 只在收包 goroutine 里调用，无需加锁。
var logErr time.Time

func logRateLimited(err error) {
	if time.Since(logErr) < time.Second {
		return
	}
	logErr = time.Now()
	log.Printf("[WinDivert] %v", err)
}

// refreshLoop 只做后台兜底刷新：1 秒足够 UI 快照用。
// 新连接识别不到时 LookupWithRefresh 会当场强制刷新，正确性不依赖这个频率；
// 之前 250ms 全表刷新在空闲时也是纯浪费（P4）。
func(i *Interceptor)refreshLoop(){ticker:=time.NewTicker(time.Second);defer ticker.Stop();for{select{case<-i.stopCh:return;case<-ticker.C:_=i.resolver.Refresh();process.RefreshIPv6TCP();process.RefreshIPv6UDP()}}}
func(i *Interceptor)handlePacket(q *sendQueue,pkt []byte,addr *winDivertAddress){if len(pkt)<1{return};version:=pkt[0]>>4;if version==6{i.handleIPv6(q,pkt,addr);return};if version!=4{return};if len(pkt)<20{return};ihl:=int(pkt[0]&0x0f)*4;if ihl<20||len(pkt)<ihl{return};proto:=pkt[9];if proto==17{i.handleIPv4UDP(q,pkt,addr,ihl);return};if proto!=6{return};if len(pkt)<ihl+4{return};i.handleIPv4TCP(q,pkt,addr,ihl)}
func(i *Interceptor)handleIPv4UDP(q *sendQueue,pkt []byte,addr *winDivertAddress,ihl int){if len(pkt)<ihl+8{i.sendPass(q,pkt,addr);return};srcPort:=binary.BigEndian.Uint16(pkt[ihl:ihl+2]);dstPort:=binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]);if dstPort!=443{i.sendPass(q,pkt,addr);return};if isPrivateOrLocal4(pkt[16],pkt[17],pkt[18],pkt[19]){i.sendPass(q,pkt,addr);return};srcIP:=binary.LittleEndian.Uint32(pkt[12:16]);i.mu.RLock();proxy4,proxy4ok:=i.proxy4,i.proxy4ok;i.mu.RUnlock();if proxy4ok&&proxy4==[4]byte{pkt[16],pkt[17],pkt[18],pkt[19]}{i.sendPass(q,pkt,addr);return};if entry,ok:=i.resolver.LookupUDPWithRefresh(process.UDPFlow{LocalIP:srcIP,LocalPort:srcPort});ok&&i.isWhitelisted(entry.Name){return};i.sendPass(q,pkt,addr)}
func (i *Interceptor) handleIPv4TCP(q *sendQueue, pkt []byte, addr *winDivertAddress, ihl int) {
	// 读取 TCP flags（offset 13）需要完整的 20 字节 TCP 头；
	// handlePacket 只校验过 ihl+4，畸形/截断包在这里必须放行而不是 panic。
	if len(pkt) < ihl+20 {
		i.sendPass(q, pkt, addr)
		return
	}
	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	flags := pkt[ihl+13]
	i.mu.RLock()
	proxy4, proxy4ok := i.proxy4, i.proxy4ok
	tproxyPort := i.tproxyPort
	i.mu.RUnlock()

	// TProxy 回程：反向 NAT
	if srcPort == tproxyPort {
		i.reverseNAT(q, pkt, addr, ihl)
		return
	}
	// 到上游代理本体的流量：保持原路径（字节比较，避免每包 net.ParseIP 分配）
	if proxy4ok && proxy4 == [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]} {
		i.sendPass(q, pkt, addr)
		return
	}
	// 本机/内网流量：保持原路径（零分配判定；net.IPv4 每包都会堆分配）
	if isPrivateOrLocal4(pkt[16], pkt[17], pkt[18], pkt[19]) {
		i.sendPass(q, pkt, addr)
		return
	}

	srcU32 := binary.LittleEndian.Uint32(pkt[12:16])
	dstU32 := binary.LittleEndian.Uint32(pkt[16:20])
	key := flowKeyV4(srcU32, dstU32, srcPort, dstPort)

	// 已定型的流：按定型结果执行，改白名单/进程识别变化不再影响它，
	// 保证不会在连接中途改道（串包/RST）。
	// 唯一例外：policyUndecided 且又出现纯 SYN（握手尚未完成）→ 允许重新评估。
	if kind, mapped, ok := i.policies.Get(key); ok {
		retry := kind == policyUndecided && isConnectionStart(flags)
		if flags&(tcpFIN|tcpRST) != 0 || retry {
			i.policies.Delete(key)
		} else {
			if kind == policyIntercept {
				// 热路径：映射端口就存在策略里，且 ConnTracker 仍有对应记录时，
				// 直接改写 —— 跳过 tracker.Set 的写锁与两次字符串分配（每包都要付）。
				if mapped != 0 && i.tracker.HasMapped(mapped) {
					i.hijackWithPort(q, pkt, addr, mapped, tproxyPort, ihl)
					return
				}
				// 映射记录已失效（代理侧连接刚结束/端口池变化）：按新连接重新登记，
				// 并把新端口写回策略，否则之后每个包都会落到这里做全量登记。
				if m := i.hijackTCP(q, pkt, addr, net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]), net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]), srcPort, dstPort, ihl); m != 0 {
					i.policies.Set(key, policyIntercept, m)
					return
				}
				// 登记失败：hijackTCP 已处置本包，这里只把这条流锁定为直连，
				// 避免端口池耗尽后每个包都重来一遍全量登记。
				i.policies.Set(key, policyPass, 0)
				return
			}
			i.sendPass(q, pkt, addr)
			return
		}
	}

	// 正在关闭的流没有定型价值
	if flags&(tcpFIN|tcpRST) != 0 {
		i.sendPass(q, pkt, addr)
		return
	}

	flow := process.Flow{LocalIP: srcU32, LocalPort: srcPort, RemoteIP: dstU32, RemotePort: dstPort}
	kind := i.decideNewFlow(isConnectionStart(flags), func() (string, bool) { return i.lookupName(flow) })
	if kind == policyIntercept {
		// srcIP/dstIP 只在"新连接真正要劫持"这一刻构造（net.IPv4 会堆分配）
		if mapped := i.hijackTCP(q, pkt, addr, net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]), net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]), srcPort, dstPort, ihl); mapped != 0 {
			i.policies.Set(key, policyIntercept, mapped)
			return
		}
		// 劫持失败：hijackTCP 已经处置过这个包（未改写的放行、已改写的丢弃，
		// 由 TCP 重传兜底），这里只锁定直连策略，绝不能再补发一次。
		i.policies.Set(key, policyPass, 0)
		return
	}
	i.policies.Set(key, kind, 0)
	i.sendPass(q, pkt, addr)
}
func(i *Interceptor)handleIPv6(q *sendQueue,pkt []byte,addr *winDivertAddress){if len(pkt)<40{i.sendPass(q,pkt,addr);return};next:=pkt[6];if next==6{i.handleIPv6TCP(q,pkt,addr);return};if next==17{i.handleIPv6UDP(q,pkt,addr);return};i.sendPass(q,pkt,addr)}
func(i *Interceptor)handleIPv6TCP(q *sendQueue,pkt []byte,addr *winDivertAddress){if len(pkt)<60{i.sendPass(q,pkt,addr);return};srcPort:=binary.BigEndian.Uint16(pkt[40:42]);dstPort:=binary.BigEndian.Uint16(pkt[42:44]);var srcIP,dstIP [16]byte;copy(srcIP[:],pkt[8:24]);copy(dstIP[:],pkt[24:40]);if isPrivateOrLocalV6(dstIP[:]){i.sendPass(q,pkt,addr);return};flags:=pkt[53]
	key:=flowKey{srcIP:srcIP,dstIP:dstIP,srcPort:srcPort,dstPort:dstPort,ver:6}
	// 已定型：白名单变更不会中途把活着的 IPv6 连接掐断；
	// 只有 undecided + 纯 SYN（握手未完成）才允许重新评估。
	if kind,_,ok:=i.policies.Get(key);ok{
		retry:=kind==policyUndecided&&isConnectionStart(flags)
		if flags&(tcpFIN|tcpRST)!=0||retry{i.policies.Delete(key)}else{
			if kind==policyIntercept{return}
			i.sendPass(q,pkt,addr);return
		}
	}
	if flags&(tcpFIN|tcpRST)!=0{i.sendPass(q,pkt,addr);return}
	kind:=i.decideNewFlow(isConnectionStart(flags),func()(string,bool){
		name,ok:=process.LookupIPv6TCP(process.IPv6TCPFlow{LocalIP:srcIP,LocalPort:srcPort,RemoteIP:dstIP,RemotePort:dstPort})
		if !ok{process.RefreshIPv6TCP();name,ok=process.LookupIPv6TCP(process.IPv6TCPFlow{LocalIP:srcIP,LocalPort:srcPort,RemoteIP:dstIP,RemotePort:dstPort})}
		if !ok||name==""{return "",false}
		return name,true
	})
	if kind==policyIntercept{i.policies.Set(key,policyIntercept,0);return}
	// 非劫持分支必须原样保存 kind。写死 policyPass 会让上面那句
	// "undecided + 纯 SYN 才允许重新评估" 的判定永远为假（IPv4 走的就是原样 kind）：
	// 首包 SYN 恰好查不到进程时，这条流会被永久定型为直连，
	// 白名单程序便绕过了"阻断回落 IPv4 再劫持"这条路。
	i.policies.Set(key,kind,0)
	i.sendPass(q,pkt,addr)
}
func(i *Interceptor)handleIPv6UDP(q *sendQueue,pkt []byte,addr *winDivertAddress){if len(pkt)<48{i.sendPass(q,pkt,addr);return};dstPort:=binary.BigEndian.Uint16(pkt[42:44]);if dstPort!=443{i.sendPass(q,pkt,addr);return};var dst6 [16]byte;copy(dst6[:],pkt[24:40]);if isPrivateOrLocalV6(dst6[:]){i.sendPass(q,pkt,addr);return};var localIP [16]byte;copy(localIP[:],pkt[8:24]);srcPort:=binary.BigEndian.Uint16(pkt[40:42]);name,ok:=process.LookupIPv6UDP(process.IPv6UDPFlow{LocalIP:localIP,LocalPort:srcPort});if !ok{process.RefreshIPv6UDP();name,ok=process.LookupIPv6UDP(process.IPv6UDPFlow{LocalIP:localIP,LocalPort:srcPort})};if ok&&i.isWhitelisted(name){return};i.sendPass(q,pkt,addr)}
func(i *Interceptor)isWhitelisted(name string)bool{i.mu.RLock();_,ok:=i.whitelist[strings.ToLower(name)];i.mu.RUnlock();return ok}
// loopbackV4 是劫持改写反复要写入的地址；在包路径上构造 net.IP 会产生堆分配。
var loopbackV4 = net.IPv4(127, 0, 0, 1).To4()

// rewriteHijack 原地把包改写成 "回环:mappedPort → 回环:tproxyPort"。
func rewriteHijack(pkt []byte, addr *winDivertAddress, ihl int, mappedPort, tproxyPort uint16) {
	copy(pkt[12:16], loopbackV4)
	copy(pkt[16:20], loopbackV4)
	binary.BigEndian.PutUint16(pkt[ihl:ihl+2], mappedPort)
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], tproxyPort)
	addr.Bits |= flagOutbound | flagLoopback
}

// hijackTCP 把包改写到 TProxy，返回分配到的映射端口；失败返回 0。
// 失败时本包的去向由它负责，调用方不得再补发（否则会重复注入同一个包）：
//   - 端口池耗尽：包还没被改写 → 放行，这条流随后锁定为直连
//   - 校验和/发送失败：包已被改写 → 丢弃，等 TCP 重传兜底
func(i *Interceptor)hijackTCP(q *sendQueue,pkt []byte,addr *winDivertAddress,origSrcIP,origDstIP net.IP,srcPort,dstPort uint16,ihl int) uint16{mappedPort,ok:=i.tracker.Set(origSrcIP,srcPort,origDstIP,dstPort,addr.IfIdx,addr.SubIfIdx);if !ok{log.Printf("[WinDivert] mapped-port pool exhausted; passing connection directly");i.sendPass(q,pkt,addr);return 0};i.mu.RLock();tp:=i.tproxyPort;i.mu.RUnlock();rewriteHijack(pkt,addr,ihl,mappedPort,tp);if err:=i.calcAndSend(q,pkt,addr);err!=nil{i.tracker.Delete("127.0.0.1",mappedPort);logRateLimited(fmt.Errorf("hijack send failed: %w",err));return 0};return mappedPort}

// hijackWithPort 是劫持热路径：映射端口直接取自策略表，不再经过 tracker.Set
// 的写锁和两次 net.IP 字符串分配——那是每个已劫持包都要付的代价。
func (i *Interceptor) hijackWithPort(q *sendQueue, pkt []byte, addr *winDivertAddress, mappedPort, tproxyPort uint16, ihl int) {
	rewriteHijack(pkt, addr, ihl, mappedPort, tproxyPort)
	if err := i.calcAndSend(q, pkt, addr); err != nil {
		logRateLimited(fmt.Errorf("hijack send failed: %w", err))
	}
}

// reverseNAT 把 TProxy 回程包改回"原始服务端 → 原始客户端"。
// 查表键几乎恒等于 127.0.0.1:映射端口（劫持时改写的目的地址），
// 用常量字符串命中，避免每包一次 net.IP.String() 分配。
func(i *Interceptor)reverseNAT(q *sendQueue,pkt []byte,addr *winDivertAddress,ihl int){d:=pkt[16:20];ipKey:="127.0.0.1";if d[0]!=127||d[1]!=0||d[2]!=0||d[3]!=1{ipKey=net.IP(d).String()};dstPort:=binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]);target,found:=i.tracker.Get(ipKey,dstPort);if !found{i.sendPass(q,pkt,addr);return};copy(pkt[12:16],target.OrigDstIP.To4());binary.BigEndian.PutUint16(pkt[ihl:ihl+2],target.OrigDstPort);copy(pkt[16:20],target.OrigSrcIP.To4());binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4],target.OrigSrcPort);if target.OrigSrcIP.IsLoopback(){addr.Bits|=flagOutbound|flagLoopback}else{addr.Bits&=^(uint32(flagOutbound)|uint32(flagLoopback))};addr.IfIdx,addr.SubIfIdx=target.OrigIfIdx,target.OrigSubIfIdx;if err:=i.calcAndSend(q,pkt,addr);err!=nil{logRateLimited(fmt.Errorf("reverse NAT failed: %w",err))}}

// calcAndSend 重算校验和后把包排队回注。
// q 为 nil 表示没有批量队列（单测/降级路径），校验和算完直接同步发送。
func(i *Interceptor)calcAndSend(q *sendQueue,pkt []byte,addr *winDivertAddress)error{i.mu.RLock();h:=i.handle;i.mu.RUnlock();if h==nil{return fmt.Errorf("WinDivert handle not ready")};if err:=h.CalcChecksums(pkt,addr);err!=nil{return err};if q==nil{return h.Send(pkt,addr)};q.push(pkt,addr);return nil}

// sendPass 把包原样排队回注。q 为 nil 时退回同步发送（无驱动句柄则丢弃）。
func(i *Interceptor)sendPass(q *sendQueue,pkt []byte,addr *winDivertAddress){
	if q==nil{
		i.mu.RLock();h:=i.handle;i.mu.RUnlock()
		if h!=nil{_ = h.Send(pkt,addr)}
		return
	}
	// 队列按"一批最多 recvBufSize 字节"预留，正常不会溢出；
	// 万一溢出就先冲刷，既保住容量也保住回注顺序。
	if q.wouldOverflow(len(pkt)){i.flushQueue(q)}
	q.push(pkt,addr)
}

// flushQueue 用一次 WinDivertSendEx 把本批排队的包全部回注。
func (i *Interceptor) flushQueue(q *sendQueue) {
	if q == nil || q.count() == 0 {
		return
	}
	i.mu.RLock()
	h := i.handle
	i.mu.RUnlock()
	if h == nil {
		q.reset()
		return
	}
	if err := h.SendBatch(q); err != nil {
		logRateLimited(fmt.Errorf("批量回注失败: %w", err))
	}
	q.reset()
}
func(i *Interceptor)ProcessStatuses()[]ProcessStatus{entries:=i.resolver.Snapshot();groups:=map[string]*ProcessStatus{};for _,e:=range entries{name:=e.Name;if name==""{continue};status:="direct";if i.isWhitelisted(name){status="proxy"};key:=fmt.Sprintf("%d|%s",e.PID,status);g:=groups[key];if g==nil{g=&ProcessStatus{Process:name,PID:e.PID,Status:status,Targets:make([]string,0,4)};groups[key]=g};g.Connections++;target:=net.JoinHostPort(ipFromUint32(e.Flow.RemoteIP).String(),fmt.Sprintf("%d",e.Flow.RemotePort));if len(g.Targets)<4{seen:=false;for _,t:=range g.Targets{if t==target{seen=true;break}};if !seen{g.Targets=append(g.Targets,target)}}};out:=make([]ProcessStatus,0,len(groups));for _,v:=range groups{out=append(out,*v)};return out}
func ipFromUint32(v uint32)net.IP{return net.IPv4(byte(v),byte(v>>8),byte(v>>16),byte(v>>24))}
func isPrivateOrLocal(ip net.IP)bool{v4:=ip.To4();if v4==nil{return true};return isPrivateOrLocal4(v4[0],v4[1],v4[2],v4[3])}

// isPrivateOrLocal4 是零分配版本，供数据包热路径使用（net.IPv4 会产生堆分配）。
func isPrivateOrLocal4(a,b,c,d byte)bool{switch{case a==0,a==10,a==127:return true;case a==169&&b==254:return true;case a==172&&b>=16&&b<=31:return true;case a==192&&b==168:return true;case a==100&&b>=64&&b<=127:return true;case a==192&&b==0&&c==0:return true;case a>=224:return true};return false}

// isPrivateOrLocalV6 与 isPrivateOrLocal 等价的 IPv6 版本。
// 必须与 IPv4 路径保持同样的豁免，否则白名单进程访问 [::1]/链路本地/ULA
// 会被"阻断 IPv6 强制回落 IPv4"的逻辑误伤成本机黑洞。
func isPrivateOrLocalV6(ip net.IP)bool{
	if v4:=ip.To4();v4!=nil{return isPrivateOrLocal4(v4[0],v4[1],v4[2],v4[3])}
	if len(ip)!=net.IPv6len{return true}
	if ip.IsLoopback()||ip.IsUnspecified()||ip.IsLinkLocalUnicast()||ip.IsLinkLocalMulticast()||ip.IsInterfaceLocalMulticast()||ip.IsMulticast(){return true}
	if ip[0]&0xfe==0xfc{return true}                 // ULA fc00::/7
	if ip[0]==0xfe&&ip[1]&0xc0==0xc0{return true}     // 已废弃的 site-local fec0::/10
	return false
}
func(i *Interceptor)Close(){i.closeOnce.Do(func(){close(i.stopCh);i.setState(stateStopped,"");if i.policies!=nil{i.policies.Close()};i.mu.Lock();h:=i.handle;i.handle=nil;i.mu.Unlock();if h!=nil{h.Close()}})}
