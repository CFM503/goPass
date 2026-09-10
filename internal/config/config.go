package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	API              APIConfig            `json:"api"`
	Outbounds        OutboundConfig       `json:"outbounds"`
	Performance      PerformanceConfig    `json:"performance"`
	System           SystemConfig         `json:"system"`
	ProcessWhitelist []string             `json:"process_whitelist"`
	AutomaticRoute   AutomaticRouteConfig `json:"automatic_route"`
}

type PerformanceConfig struct{BufferSize int `json:"buffer_size"`;TCPNoDelay bool `json:"tcp_nodelay"`;TCPKeepAlive bool `json:"tcp_keep_alive"`;KeepAlivePeriod int `json:"keep_alive_period"`;TCPLinger int `json:"tcp_linger"`}
func ClampBufferSize(size int) int{const min=32*1024;const max=1024*1024;if size<min{return min};if size>max{return max};return size}
type APIConfig struct{ListenAddr string `json:"listen_addr"`;WSRefreshInterval int `json:"ws_refresh_interval"`;UIConnLimit int `json:"ui_conn_limit"`}
type SystemConfig struct{TProxyPort int `json:"tproxy_port"`;ConnTrackGCInterval int `json:"conn_track_gc_interval"`;ConnTrackTTL int `json:"conn_track_ttl"`}
type OutboundConfig struct{Servers []Server `json:"servers"`}
type Server struct{Tag string `json:"tag"`;Type string `json:"type"`;Address string `json:"address"`;Port int `json:"port"`;Username string `json:"username"`;Password string `json:"password"`}
type AutomaticRouteConfig struct{Enabled bool `json:"enabled"`;CheckInterval int `json:"check_interval"`;StandbyCheckInterval int `json:"standby_check_interval"`;RecoverCheckInterval int `json:"recover_check_interval"`;SwitchThreshold float64 `json:"switch_threshold"`;SwitchCooldown int `json:"switch_cooldown"`;MinimumStableTime int `json:"minimum_stable_time"`;FailureThreshold int `json:"failure_threshold"`;RecoveryThreshold int `json:"recovery_threshold"`;PeakMode string `json:"peak_mode"`;PeakStartHour int `json:"peak_start_hour"`;PeakEndHour int `json:"peak_end_hour"`;HistoryWindow int `json:"history_window"`;StandbyCount int `json:"standby_count"`;MaxProbeConcurrency int `json:"max_probe_concurrency"`;HistoryFile string `json:"history_file"`;HistorySaveInterval int `json:"history_save_interval"`;Routes []RouteConfig `json:"routes"`}
type RouteConfig struct{ID string `json:"id"`;Name string `json:"name"`;Address string `json:"address"`;Port int `json:"port"`;Protocol string `json:"protocol"`;Type string `json:"type"`}
func DefaultAutomaticRouteConfig()AutomaticRouteConfig{return AutomaticRouteConfig{Enabled:false,CheckInterval:5,StandbyCheckInterval:30,RecoverCheckInterval:120,SwitchThreshold:5,SwitchCooldown:60,MinimumStableTime:30,FailureThreshold:3,RecoveryThreshold:3,PeakMode:"auto",PeakStartHour:18,PeakEndHour:23,HistoryWindow:60,StandbyCount:3,MaxProbeConcurrency:4,HistoryFile:"routes_history.json",HistorySaveInterval:300,Routes:[]RouteConfig{{ID:"goway-default",Name:"GOWAY Default",Address:"127.0.0.1",Port:9192,Protocol:"socks5",Type:"goway"}}}}
func NormalizeAutomaticRoute(a AutomaticRouteConfig)AutomaticRouteConfig{d:=DefaultAutomaticRouteConfig();if a.CheckInterval<=0{a.CheckInterval=d.CheckInterval};if a.StandbyCheckInterval<=0{a.StandbyCheckInterval=d.StandbyCheckInterval};if a.RecoverCheckInterval<=0{a.RecoverCheckInterval=d.RecoverCheckInterval};if a.SwitchThreshold<=0{a.SwitchThreshold=d.SwitchThreshold};if a.SwitchCooldown<0{a.SwitchCooldown=0}else if a.SwitchCooldown==0{a.SwitchCooldown=d.SwitchCooldown};if a.MinimumStableTime<0{a.MinimumStableTime=0}else if a.MinimumStableTime==0{a.MinimumStableTime=d.MinimumStableTime};if a.FailureThreshold<=0{a.FailureThreshold=d.FailureThreshold};if a.RecoveryThreshold<=0{a.RecoveryThreshold=d.RecoveryThreshold};if a.PeakMode==""{a.PeakMode=d.PeakMode};if a.PeakStartHour==0&&a.PeakEndHour==0{a.PeakStartHour,a.PeakEndHour=d.PeakStartHour,d.PeakEndHour};if a.HistoryWindow<=0{a.HistoryWindow=d.HistoryWindow};if a.StandbyCount<=0{a.StandbyCount=d.StandbyCount};if a.MaxProbeConcurrency<=0{a.MaxProbeConcurrency=d.MaxProbeConcurrency};if a.HistoryFile==""{a.HistoryFile=d.HistoryFile};if a.HistorySaveInterval<=0{a.HistorySaveInterval=d.HistorySaveInterval};if len(a.Routes)==0{a.Routes=d.Routes};return a}
func DefaultConfig()*Config{return &Config{API:APIConfig{ListenAddr:"127.0.0.1:8080",WSRefreshInterval:5,UIConnLimit:20},Outbounds:OutboundConfig{Servers:[]Server{{Tag:"proxy",Type:"socks5",Address:"127.0.0.1",Port:9192}}},Performance:PerformanceConfig{BufferSize:256*1024,TCPNoDelay:true,TCPKeepAlive:true,KeepAlivePeriod:15,TCPLinger:-1},System:SystemConfig{TProxyPort:7893,ConnTrackGCInterval:15,ConnTrackTTL:30},ProcessWhitelist:[]string{},AutomaticRoute:DefaultAutomaticRouteConfig()}}
func(c *Config)UnmarshalJSON(data []byte)error{type Alias Config;aux:=(*Alias)(c);if err:=json.Unmarshal(data,aux);err!=nil{return err};d:=DefaultConfig();if c.API.ListenAddr==""{c.API.ListenAddr=d.API.ListenAddr};if c.API.WSRefreshInterval<=0{c.API.WSRefreshInterval=d.API.WSRefreshInterval};if c.API.UIConnLimit<=0{c.API.UIConnLimit=d.API.UIConnLimit};if c.System.TProxyPort==0{c.System=d.System}else{if c.System.ConnTrackGCInterval<=0{c.System.ConnTrackGCInterval=d.System.ConnTrackGCInterval};if c.System.ConnTrackTTL<=0{c.System.ConnTrackTTL=d.System.ConnTrackTTL}};if c.Performance.BufferSize==0{c.Performance=d.Performance}else{c.Performance.BufferSize=ClampBufferSize(c.Performance.BufferSize)};c.AutomaticRoute=NormalizeAutomaticRoute(c.AutomaticRoute);return nil}
func Load(path string)(*Config,error){data,err:=os.ReadFile(path);if err!=nil{return nil,err};var c Config;if err:=json.Unmarshal(data,&c);err!=nil{return nil,err};return &c,nil}
func(c *Config)Save(path string)error{data,err:=json.MarshalIndent(c,"","  ");if err!=nil{return err};return os.WriteFile(path,data,0644)}
