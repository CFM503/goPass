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

type winDivertAddress struct { Timestamp int64; Bits uint32; Reserved2 uint32; IfIdx uint32; SubIfIdx uint32; Data [60]byte }
type winDivertDLL struct { dll *windows.DLL; procOpen *windows.Proc; procRecv *windows.Proc; procSend *windows.Proc; procClose *windows.Proc; procCalcChecks *windows.Proc }
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
func loadWinDivert()(*winDivertDLL,error){wdOnce.Do(func(){stopAndRemoveWinDivertDriver();cwd,err:=os.Getwd();if err!=nil{cwd="."};dllPath:=filepath.Join(cwd,"WinDivert.dll");sysPath:=filepath.Join(cwd,"WinDivert64.sys");if !fileContentMatch(dllPath,windivertDLL){if err:=os.WriteFile(dllPath,windivertDLL,0755);err!=nil{wdErr=err;return}};if !fileContentMatch(sysPath,windivertSYS){if err:=extractSysFile(sysPath,windivertSYS);err!=nil&&!fileContentMatch(sysPath,windivertSYS){wdErr=err;return}};dll,err:=windows.LoadDLL(dllPath);if err!=nil{wdErr=err;return};find:=func(n string)*windows.Proc{p,e:=dll.FindProc(n);if e!=nil{wdErr=e;return nil};return p};wdDLL=&winDivertDLL{dll:dll,procOpen:find("WinDivertOpen"),procRecv:find("WinDivertRecv"),procSend:find("WinDivertSend"),procClose:find("WinDivertClose"),procCalcChecks:find("WinDivertHelperCalcChecksums")}});return wdDLL,wdErr}
type winDivertHandle struct{handle windows.Handle;dll *winDivertDLL}
func wdOpen(filter string,layer,priority int,flags uint64)(*winDivertHandle,error){dll,err:=loadWinDivert();if err!=nil{return nil,err};p,err:=syscall.BytePtrFromString(filter);if err!=nil{return nil,err};ret,_,eno:=dll.procOpen.Call(uintptr(unsafe.Pointer(p)),uintptr(layer),uintptr(priority),uintptr(flags));if ret==uintptr(windows.InvalidHandle){return nil,fmt.Errorf("WinDivertOpen failed: %w",eno)};return &winDivertHandle{handle:windows.Handle(ret),dll:dll},nil}
func(h *winDivertHandle)Recv(buf []byte)(int,*winDivertAddress,error){if len(buf)==0{return 0,nil,fmt.Errorf("empty receive buffer")};var addr winDivertAddress;var n uint32;ret,_,eno:=h.dll.procRecv.Call(uintptr(h.handle),uintptr(unsafe.Pointer(&buf[0])),uintptr(len(buf)),uintptr(unsafe.Pointer(&n)),uintptr(unsafe.Pointer(&addr)));if ret==0{return 0,nil,fmt.Errorf("WinDivertRecv: %w",eno)};return int(n),&addr,nil}
func(h *winDivertHandle)Send(pkt []byte,addr *winDivertAddress)error{if len(pkt)==0{return fmt.Errorf("empty packet")};var n uint32;ret,_,eno:=h.dll.procSend.Call(uintptr(h.handle),uintptr(unsafe.Pointer(&pkt[0])),uintptr(len(pkt)),uintptr(unsafe.Pointer(&n)),uintptr(unsafe.Pointer(addr)));if ret==0{return fmt.Errorf("WinDivertSend: %w",eno)};return nil}
func(h *winDivertHandle)CalcChecksums(pkt []byte,addr *winDivertAddress)error{if len(pkt)==0{return fmt.Errorf("empty packet")};ret,_,eno:=h.dll.procCalcChecks.Call(uintptr(unsafe.Pointer(&pkt[0])),uintptr(len(pkt)),uintptr(unsafe.Pointer(addr)),0);if ret==0{return fmt.Errorf("WinDivertHelperCalcChecksums: %w",eno)};return nil}
func(h *winDivertHandle)Close(){if h!=nil&&h.handle!=windows.InvalidHandle{_,_,_=h.dll.procClose.Call(uintptr(h.handle));h.handle=windows.InvalidHandle}}
func isProcessElevated()bool{var token windows.Token;if err:=windows.OpenProcessToken(windows.CurrentProcess(),windows.TOKEN_QUERY,&token);err!=nil{return false};defer token.Close();return token.IsElevated()}

type Interceptor struct{handle *winDivertHandle;mu sync.RWMutex;tracker *ConnTracker;proxyIP string;proxyPort uint16;tproxyPort uint16;stopCh chan struct{};closeOnce sync.Once;resolver *process.Resolver;whitelist map[string]struct{}}
func NewInterceptor(tracker *ConnTracker,proxyIP string,proxyPort,tproxyPort uint16,whitelist []string)*Interceptor{i:=&Interceptor{tracker:tracker,proxyIP:proxyIP,proxyPort:proxyPort,tproxyPort:tproxyPort,stopCh:make(chan struct{}),resolver:process.NewResolver(),whitelist:make(map[string]struct{})};i.SetWhitelist(whitelist);return i}
func(i *Interceptor)SetWhitelist(list []string){m:=make(map[string]struct{},len(list));for _,name:=range list{name=strings.TrimSpace(strings.ToLower(name));if name!=""{m[name]=struct{}{}}};i.mu.Lock();i.whitelist=m;i.mu.Unlock()}
func(i *Interceptor)GetWhitelist()[]string{i.mu.RLock();out:=make([]string,0,len(i.whitelist));for n:=range i.whitelist{out=append(out,n)};i.mu.RUnlock();return out}
func(i *Interceptor)SetProxyAddr(ip string,port uint16){i.mu.Lock();i.proxyIP,i.proxyPort=ip,port;i.mu.Unlock()}

// Keep one Network-layer WinDivert handle. WinDivert handles at the same
// priority must not overlap; QUIC/IPv6 filtering therefore lives in this
// primary handle instead of separate UDP/IPv6 blockers.
func(i *Interceptor)buildFilter()string{i.mu.RLock();proxyIP:=i.proxyIP;tproxyPort:=i.tproxyPort;i.mu.RUnlock();tcp:="(outbound and ip and tcp and ip.DstAddr != 127.0.0.1";if pip:=net.ParseIP(proxyIP);pip!=nil&&pip.To4()!=nil&&!pip.IsLoopback(){tcp+=fmt.Sprintf(" and ip.DstAddr != %s",pip.To4().String())};tcp+=")";quic:="(outbound and ip and udp and udp.DstPort == 443 and ip.DstAddr != 127.0.0.1";if pip:=net.ParseIP(proxyIP);pip!=nil&&pip.To4()!=nil&&!pip.IsLoopback(){quic+=fmt.Sprintf(" and ip.DstAddr != %s",pip.To4().String())};quic+=")";return fmt.Sprintf("%s or %s or (outbound and ipv6) or (outbound and ip and tcp and tcp.SrcPort == %d)",tcp,quic,tproxyPort)}
func(i *Interceptor)preflight()error{if !isProcessElevated(){return fmt.Errorf("需要管理员权限：请右键 GoPass.exe 选择“以管理员身份运行”")};h,err:=wdOpen(i.buildFilter(),layerNetwork,priorityDefault,0);if err!=nil{return fmt.Errorf("WinDivert 初始化/驱动加载失败：%w",err)};h.Close();return nil}
func(i *Interceptor)Start()error{h,err:=wdOpen(i.buildFilter(),layerNetwork,priorityDefault,0);if err!=nil{return fmt.Errorf("WinDivert 启动失败：%w",err)};i.mu.Lock();i.handle=h;i.mu.Unlock();_=i.resolver.Refresh();process.RefreshIPv6TCP();process.RefreshIPv6UDP();log.Println("[WinDivert] unified TCP/QUIC/IPv6 interception ready");go i.refreshLoop();buf:=make([]byte,65535);for{select{case<-i.stopCh:return nil;default:};i.mu.RLock();h=i.handle;i.mu.RUnlock();if h==nil{return nil};n,addr,err:=h.Recv(buf);if err!=nil{select{case<-i.stopCh:return nil;default:time.Sleep(5*time.Millisecond)};continue};if n>0&&n<=len(buf){i.handlePacket(buf[:n],addr)}}}
func(i *Interceptor)refreshLoop(){ticker:=time.NewTicker(250*time.Millisecond);defer ticker.Stop();for{select{case<-i.stopCh:return;case<-ticker.C:_=i.resolver.Refresh();process.RefreshIPv6TCP();process.RefreshIPv6UDP()}}}
func(i *Interceptor)handlePacket(pkt []byte,addr *winDivertAddress){if len(pkt)<1{return};version:=pkt[0]>>4;if version==6{i.handleIPv6(pkt,addr);return};if version!=4{return};if len(pkt)<20{return};ihl:=int(pkt[0]&0x0f)*4;if ihl<20||len(pkt)<ihl{return};proto:=pkt[9];if proto==17{i.handleIPv4UDP(pkt,addr,ihl);return};if proto!=6{return};if len(pkt)<ihl+4{return};i.handleIPv4TCP(pkt,addr,ihl)}
func(i *Interceptor)handleIPv4UDP(pkt []byte,addr *winDivertAddress,ihl int){if len(pkt)<ihl+8{i.sendPass(pkt,addr);return};srcPort:=binary.BigEndian.Uint16(pkt[ihl:ihl+2]);dstPort:=binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]);if dstPort!=443{i.sendPass(pkt,addr);return};srcIP:=binary.LittleEndian.Uint32(pkt[12:16]);i.mu.RLock();proxyIP:=i.proxyIP;i.mu.RUnlock();if proxyIP!=""{if pip:=net.ParseIP(proxyIP);pip!=nil&&pip.Equal(net.IPv4(pkt[16],pkt[17],pkt[18],pkt[19])){i.sendPass(pkt,addr);return}};if entry,ok:=i.resolver.LookupUDPWithRefresh(process.UDPFlow{LocalIP:srcIP,LocalPort:srcPort});ok&&i.isWhitelisted(entry.Name){return};i.sendPass(pkt,addr)}
func(i *Interceptor)handleIPv4TCP(pkt []byte,addr *winDivertAddress,ihl int){srcIP:=net.IPv4(pkt[12],pkt[13],pkt[14],pkt[15]);dstIP:=net.IPv4(pkt[16],pkt[17],pkt[18],pkt[19]);srcPort:=binary.BigEndian.Uint16(pkt[ihl:ihl+2]);dstPort:=binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]);i.mu.RLock();proxyIP:=i.proxyIP;tproxyPort:=i.tproxyPort;i.mu.RUnlock();if srcPort==tproxyPort{i.reverseNAT(pkt,addr,ihl);return};if proxyIP!=""{if pip:=net.ParseIP(proxyIP);pip!=nil&&pip.Equal(dstIP){i.sendPass(pkt,addr);return}};if isPrivateOrLocal(dstIP){i.sendPass(pkt,addr);return};flow:=process.Flow{LocalIP:binary.LittleEndian.Uint32(pkt[12:16]),LocalPort:srcPort,RemoteIP:binary.LittleEndian.Uint32(pkt[16:20]),RemotePort:dstPort};entry,ok:=i.resolver.LookupWithRefresh(flow);if !ok||!i.isWhitelisted(entry.Name){i.sendPass(pkt,addr);return};i.hijackTCP(pkt,addr,srcIP,dstIP,srcPort,dstPort,ihl)}
func(i *Interceptor)handleIPv6(pkt []byte,addr *winDivertAddress){if len(pkt)<40{i.sendPass(pkt,addr);return};next:=pkt[6];if next==6{i.handleIPv6TCP(pkt,addr);return};if next==17{i.handleIPv6UDP(pkt,addr);return};i.sendPass(pkt,addr)}
func(i *Interceptor)handleIPv6TCP(pkt []byte,addr *winDivertAddress){if len(pkt)<60{i.sendPass(pkt,addr);return};srcPort:=binary.BigEndian.Uint16(pkt[40:42]);dstPort:=binary.BigEndian.Uint16(pkt[42:44]);var srcIP,dstIP [16]byte;copy(srcIP[:],pkt[8:24]);copy(dstIP[:],pkt[24:40]);name,ok:=process.LookupIPv6TCP(process.IPv6TCPFlow{LocalIP:srcIP,LocalPort:srcPort,RemoteIP:dstIP,RemotePort:dstPort});if !ok{process.RefreshIPv6TCP();name,ok=process.LookupIPv6TCP(process.IPv6TCPFlow{LocalIP:srcIP,LocalPort:srcPort,RemoteIP:dstIP,RemotePort:dstPort})};if ok&&i.isWhitelisted(name){return};i.sendPass(pkt,addr)}
func(i *Interceptor)handleIPv6UDP(pkt []byte,addr *winDivertAddress){if len(pkt)<48{i.sendPass(pkt,addr);return};dstPort:=binary.BigEndian.Uint16(pkt[42:44]);if dstPort!=443{i.sendPass(pkt,addr);return};var localIP [16]byte;copy(localIP[:],pkt[8:24]);srcPort:=binary.BigEndian.Uint16(pkt[40:42]);name,ok:=process.LookupIPv6UDP(process.IPv6UDPFlow{LocalIP:localIP,LocalPort:srcPort});if !ok{process.RefreshIPv6UDP();name,ok=process.LookupIPv6UDP(process.IPv6UDPFlow{LocalIP:localIP,LocalPort:srcPort})};if ok&&i.isWhitelisted(name){return};i.sendPass(pkt,addr)}
func(i *Interceptor)isWhitelisted(name string)bool{i.mu.RLock();_,ok:=i.whitelist[strings.ToLower(name)];i.mu.RUnlock();return ok}
func(i *Interceptor)hijackTCP(pkt []byte,addr *winDivertAddress,origSrcIP,origDstIP net.IP,srcPort,dstPort uint16,ihl int){mappedPort,ok:=i.tracker.Set(origSrcIP,srcPort,origDstIP,dstPort,addr.IfIdx,addr.SubIfIdx);if !ok{log.Printf("[WinDivert] mapped-port pool exhausted; passing connection directly");i.sendPass(pkt,addr);return};loop:=net.IPv4(127,0,0,1).To4();copy(pkt[12:16],loop);copy(pkt[16:20],loop);binary.BigEndian.PutUint16(pkt[ihl:ihl+2],mappedPort);i.mu.RLock();tp:=i.tproxyPort;i.mu.RUnlock();binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4],tp);addr.Bits|=flagOutbound|flagLoopback;if err:=i.calcAndSend(pkt,addr);err!=nil{i.tracker.Delete("127.0.0.1",mappedPort);log.Printf("[WinDivert] hijack send failed: %v",err)}}
func(i *Interceptor)reverseNAT(pkt []byte,addr *winDivertAddress,ihl int){dstIP:=net.IP(pkt[16:20]);dstPort:=binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]);target,found:=i.tracker.Get(dstIP.String(),dstPort);if !found{i.sendPass(pkt,addr);return};copy(pkt[12:16],target.OrigDstIP.To4());binary.BigEndian.PutUint16(pkt[ihl:ihl+2],target.OrigDstPort);copy(pkt[16:20],target.OrigSrcIP.To4());binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4],target.OrigSrcPort);if target.OrigSrcIP.IsLoopback(){addr.Bits|=flagOutbound|flagLoopback}else{addr.Bits&=^(uint32(flagOutbound)|uint32(flagLoopback))};addr.IfIdx,addr.SubIfIdx=target.OrigIfIdx,target.OrigSubIfIdx;if err:=i.calcAndSend(pkt,addr);err!=nil{log.Printf("[WinDivert] reverse NAT failed: %v",err)}}
func(i *Interceptor)calcAndSend(pkt []byte,addr *winDivertAddress)error{i.mu.RLock();h:=i.handle;i.mu.RUnlock();if h==nil{return fmt.Errorf("WinDivert handle not ready")};if err:=h.CalcChecksums(pkt,addr);err!=nil{return err};return h.Send(pkt,addr)}
func(i *Interceptor)sendPass(pkt []byte,addr *winDivertAddress){i.mu.RLock();h:=i.handle;i.mu.RUnlock();if h!=nil{_=h.Send(pkt,addr)}}
func(i *Interceptor)ProcessStatuses()[]ProcessStatus{entries:=i.resolver.Snapshot();groups:=map[string]*ProcessStatus{};for _,e:=range entries{name:=e.Name;if name==""{continue};status:="direct";if i.isWhitelisted(name){status="proxy"};key:=fmt.Sprintf("%d|%s",e.PID,status);g:=groups[key];if g==nil{g=&ProcessStatus{Process:name,PID:e.PID,Status:status,Targets:make([]string,0,4)};groups[key]=g};g.Connections++;target:=net.JoinHostPort(ipFromUint32(e.Flow.RemoteIP).String(),fmt.Sprintf("%d",e.Flow.RemotePort));if len(g.Targets)<4{seen:=false;for _,t:=range g.Targets{if t==target{seen=true;break}};if !seen{g.Targets=append(g.Targets,target)}}};out:=make([]ProcessStatus,0,len(groups));for _,v:=range groups{out=append(out,*v)};return out}
func ipFromUint32(v uint32)net.IP{return net.IPv4(byte(v),byte(v>>8),byte(v>>16),byte(v>>24))}
func isPrivateOrLocal(ip net.IP)bool{v4:=ip.To4();if v4==nil{return true};switch{case v4[0]==0,v4[0]==10,v4[0]==127:return true;case v4[0]==169&&v4[1]==254:return true;case v4[0]==172&&v4[1]>=16&&v4[1]<=31:return true;case v4[0]==192&&v4[1]==168:return true;case v4[0]==100&&v4[1]>=64&&v4[1]<=127:return true;case v4[0]==192&&v4[1]==0&&v4[2]==0:return true;case v4[0]>=224:return true};return false}
func(i *Interceptor)Close(){i.closeOnce.Do(func(){close(i.stopCh);i.mu.Lock();h:=i.handle;i.handle=nil;i.mu.Unlock();if h!=nil{h.Close()}})}
