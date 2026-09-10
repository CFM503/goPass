package engine

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/version"
)

type Engine struct{cfg *config.Config;cfgMu sync.RWMutex;tracker *ConnTracker;tproxy *TProxy;interceptor *Interceptor;udpBlocker *UDPBlocker;Stats *Stats}
type Stats struct{PID int;Connections int;RxBytes int64;TxBytes int64;mu sync.RWMutex;active map[string]map[string]interface{}}
type ProcessStatus struct{Process string `json:"process"`;PID uint32 `json:"pid"`;Status string `json:"status"`;Connections int `json:"connections"`;Targets []string `json:"targets"`}
func(s *Stats)AddActiveConn(info map[string]interface{}){id,_:=info["id"].(string);s.mu.Lock();if s.active==nil{s.active=make(map[string]map[string]interface{})};if _,ok:=s.active[id];!ok{s.Connections++};s.active[id]=info;s.mu.Unlock()}
func(s *Stats)RemoveActiveConn(id string){s.mu.Lock();if _,ok:=s.active[id];ok{delete(s.active,id);if s.Connections>0{s.Connections--}};s.mu.Unlock()}
func(s *Stats)GetActive()[]map[string]interface{}{s.mu.RLock();defer s.mu.RUnlock();out:=make([]map[string]interface{},0,len(s.active));for _,item:=range s.active{c:=make(map[string]interface{},len(item));for k,v:=range item{c[k]=v};out=append(out,c)};return out}
func New(cfg *config.Config)(*Engine,error){stats:=&Stats{PID:os.Getpid(),active:make(map[string]map[string]interface{})};return &Engine{cfg:cfg,tracker:NewConnTracker(cfg.System.ConnTrackGCInterval,cfg.System.ConnTrackTTL,uint16(cfg.System.TProxyPort)),Stats:stats},nil}
func(e *Engine)Start()error{log.Printf("[Engine] GoPass %s starting, PID=%d",version.Version,e.Stats.PID);proxyAddr,proxyType:="","";for _,srv:=range e.cfg.Outbounds.Servers{if srv.Type=="socks5"||srv.Type=="http"{proxyAddr=fmt.Sprintf("%s:%d",srv.Address,srv.Port);proxyType=srv.Type;break}};if proxyAddr==""{return fmt.Errorf("no socks5 or http upstream configured")};proxyHost,proxyPort,err:=parseAddr(proxyAddr);if err!=nil{return fmt.Errorf("invalid upstream address: %w",err)};tp,err:=NewTProxy(e.tracker,proxyType,proxyAddr,e.Stats,e.cfg.Performance,e.cfg.System.TProxyPort);if err!=nil{return fmt.Errorf("TProxy 初始化失败：%w",err)};proxyIP:=proxyFilterIP(proxyHost);i:=NewInterceptor(e.tracker,proxyIP,uint16(proxyPort),uint16(e.cfg.System.TProxyPort),e.cfg.ProcessWhitelist);u:=NewUDPBlocker(i.resolver,proxyIP,e.cfg.ProcessWhitelist);if err:=i.preflight();err!=nil{_=tp.Close();return err};if err:=u.preflight();err!=nil{_=tp.Close();return err};e.tproxy=tp;e.interceptor=i;e.udpBlocker=u;go tp.Accept();go func(){if err:=i.Start();err!=nil{log.Printf("[WinDivert] runtime stopped: %v",err)}}();go func(){if err:=u.Start();err!=nil{log.Printf("[WinDivert] UDP/443 blocker stopped: %v",err)}}();log.Printf("[Engine] ready: upstream=%s tproxy=%d whitelist=%v",proxyAddr,e.cfg.System.TProxyPort,e.cfg.ProcessWhitelist);return nil}
func(e *Engine)UpdatePerformance(p config.PerformanceConfig){p.BufferSize=config.ClampBufferSize(p.BufferSize);e.cfgMu.Lock();e.cfg.Performance=p;e.cfgMu.Unlock();if e.tproxy!=nil{e.tproxy.UpdatePerformance(p)}}
func(e *Engine)UpdateUpstream(pt,addr string,port int,save string){newAddr:=fmt.Sprintf("%s:%d",addr,port);e.cfgMu.Lock();if len(e.cfg.Outbounds.Servers)==0{e.cfg.Outbounds.Servers=[]config.Server{{Tag:"proxy",Type:pt,Address:addr,Port:port}}}else{e.cfg.Outbounds.Servers[0].Type,e.cfg.Outbounds.Servers[0].Address,e.cfg.Outbounds.Servers[0].Port=pt,addr,port};e.cfgMu.Unlock();if e.tproxy!=nil{e.tproxy.UpdateUpstream(pt,newAddr)};if e.interceptor!=nil{e.interceptor.SetProxyAddr(proxyFilterIP(addr),uint16(port))};if e.udpBlocker!=nil{e.udpBlocker.SetProxyIP(proxyFilterIP(addr))};if save!=""{_=e.SaveConfig(save)}}
func(e *Engine)UpdateUIConfig(ws,limit int){if ws<1{ws=5};if limit<1{limit=20};e.cfgMu.Lock();e.cfg.API.WSRefreshInterval=ws;e.cfg.API.UIConnLimit=limit;e.cfgMu.Unlock()}
func(e *Engine)UpdateProcessWhitelist(list []string,save string){clean:=make([]string,0,len(list));seen:=map[string]struct{}{};for _,n:=range list{n=strings.TrimSpace(strings.ToLower(n));if n==""{continue};if _,ok:=seen[n];ok{continue};seen[n]=struct{}{};clean=append(clean,n)};e.cfgMu.Lock();e.cfg.ProcessWhitelist=clean;e.cfgMu.Unlock();if e.interceptor!=nil{e.interceptor.SetWhitelist(clean)};if e.udpBlocker!=nil{e.udpBlocker.SetWhitelist(clean)};if save!=""{_=e.SaveConfig(save)}}
func(e *Engine)GetProcessWhitelist()[]string{e.cfgMu.RLock();defer e.cfgMu.RUnlock();return append([]string(nil),e.cfg.ProcessWhitelist...)}
func(e *Engine)GetProcessStatuses()[]ProcessStatus{if e.interceptor==nil{return []ProcessStatus{}};return e.interceptor.ProcessStatuses()}
func(e *Engine)ResetConfig(path string)error{def:=config.DefaultConfig();def.ProcessWhitelist=nil;e.cfgMu.Lock();e.cfg=def;e.cfgMu.Unlock();if e.tproxy!=nil{e.tproxy.UpdatePerformance(def.Performance);for _,srv:=range def.Outbounds.Servers{if srv.Type=="socks5"||srv.Type=="http"{e.tproxy.UpdateUpstream(srv.Type,fmt.Sprintf("%s:%d",srv.Address,srv.Port));if e.interceptor!=nil{e.interceptor.SetProxyAddr(proxyFilterIP(srv.Address),uint16(srv.Port))};if e.udpBlocker!=nil{e.udpBlocker.SetProxyIP(proxyFilterIP(srv.Address))};break}}};if e.interceptor!=nil{e.interceptor.SetWhitelist(nil)};if e.udpBlocker!=nil{e.udpBlocker.SetWhitelist(nil)};if path!=""{return e.SaveConfig(path)};return nil}
func(e *Engine)GetConfig()*config.Config{e.cfgMu.RLock();defer e.cfgMu.RUnlock();clone:=*e.cfg;clone.Outbounds.Servers=append([]config.Server(nil),e.cfg.Outbounds.Servers...);clone.ProcessWhitelist=append([]string(nil),e.cfg.ProcessWhitelist...);return &clone}
func(e *Engine)SaveConfig(path string)error{e.cfgMu.RLock();defer e.cfgMu.RUnlock();return e.cfg.Save(path)}
func(e *Engine)Stop(){if e.udpBlocker!=nil{e.udpBlocker.Close()};if e.interceptor!=nil{e.interceptor.Close()};if e.tproxy!=nil{_=e.tproxy.Close()};if e.tracker!=nil{e.tracker.Close()};CleanUpOnShutdown()}
func parseAddr(addr string)(string,int,error){host,port,err:=net.SplitHostPort(addr);if err!=nil{return "",0,err};p,err:=strconv.Atoi(port);if err!=nil||p<=0||p>65535{return "",0,fmt.Errorf("invalid port: %s",port)};return host,p,nil}
func proxyFilterIP(host string)string{if ip:=net.ParseIP(host);ip!=nil&&ip.To4()!=nil&&!ip.IsLoopback(){return ip.To4().String()};ips,err:=net.LookupIP(host);if err!=nil{return ""};for _,ip:=range ips{if v4:=ip.To4();v4!=nil&&!v4.IsLoopback(){return v4.String()}};return ""}
