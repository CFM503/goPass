package config

import (
	"encoding/json"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Performance.BufferSize != 256*1024 { t.Errorf("default BufferSize = %d, want 262144", c.Performance.BufferSize) }
	if !c.Performance.TCPNoDelay { t.Error("default TCPNoDelay should be true") }
	if !c.Performance.TCPKeepAlive { t.Error("default TCPKeepAlive should be true") }
	if c.Performance.KeepAlivePeriod != 15 { t.Errorf("default KeepAlivePeriod = %d, want 15", c.Performance.KeepAlivePeriod) }
	if c.Performance.TCPLinger != -1 { t.Errorf("default TCPLinger = %d, want -1", c.Performance.TCPLinger) }
	if len(c.Outbounds.Servers) != 1 || c.Outbounds.Servers[0].Port != 9192 { t.Errorf("unexpected upstream defaults: %+v", c.Outbounds.Servers) }
}

func TestClampBufferSize(t *testing.T) {
	tests := []struct{ input, expected int }{{0,32*1024},{-1,32*1024},{32767,32768},{32768,32768},{256*1024,256*1024},{512*1024,512*1024},{1024*1024,1024*1024},{1024*1024+1,1024*1024},{2*1024*1024,1024*1024}}
	for _,tt:=range tests{if got:=ClampBufferSize(tt.input);got!=tt.expected{t.Errorf("ClampBufferSize(%d) = %d, want %d",tt.input,got,tt.expected)}}
}

func TestJSONDoesNotRestoreRemovedSplitConfig(t *testing.T) {
	legacy := `{"split":{"enabled":true,"mode":"geo"},"routing":{"mode":"global"},"api":{},"system":{}}`
	var c Config
	if err:=json.Unmarshal([]byte(legacy),&c);err!=nil{t.Fatal(err)}
	data,err:=json.Marshal(c);if err!=nil{t.Fatal(err)}
	var roundTrip map[string]interface{};if err:=json.Unmarshal(data,&roundTrip);err!=nil{t.Fatal(err)}
	if _,ok:=roundTrip["split"];ok{t.Fatal("removed split configuration must not be serialized")}
	if _,ok:=roundTrip["routing"];ok{t.Fatal("removed routing configuration must not be serialized")}
}

func TestAutomaticRouteConfigDefaults(t *testing.T) {
	c:=DefaultConfig();if c.AutomaticRoute.CheckInterval!=5{t.Errorf("CheckInterval = %d, want 5",c.AutomaticRoute.CheckInterval)};if c.AutomaticRoute.SwitchThreshold!=5.0{t.Errorf("SwitchThreshold = %f, want 5.0",c.AutomaticRoute.SwitchThreshold)};if c.AutomaticRoute.FailureThreshold!=3{t.Errorf("FailureThreshold = %d, want 3",c.AutomaticRoute.FailureThreshold)};if c.AutomaticRoute.RecoveryThreshold!=3{t.Errorf("RecoveryThreshold = %d, want 3",c.AutomaticRoute.RecoveryThreshold)};if len(c.AutomaticRoute.Routes)==0{t.Error("default should contain one route")}
}
