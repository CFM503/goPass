package controller

import (
	"sync"
	"testing"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

func TestRouteStateMachine(t *testing.T) {
	r := NewRoute("r1", "Route 1", "127.0.0.1", 1080, "socks5", "goway")

	// 初始状态为 UNKNOWN
	if r.GetState() != StateUnknown {
		t.Fatalf("expected UNKNOWN, got %s", r.GetState())
	}

	// UNKNOWN -> READY
	if err := r.TransitionTo(StateReady); err != nil {
		t.Fatalf("expected UNKNOWN -> READY ok, got error: %v", err)
	}

	// READY -> ACTIVE
	if err := r.TransitionTo(StateActive); err != nil {
		t.Fatalf("expected READY -> ACTIVE ok, got error: %v", err)
	}

	// 严禁: ACTIVE -> ACTIVE
	if err := r.TransitionTo(StateActive); err == nil {
		t.Fatal("expected error on ACTIVE -> ACTIVE")
	}

	// 严禁: ACTIVE -> FAILED 直接跳跃
	if err := r.TransitionTo(StateFailed); err == nil {
		t.Fatal("expected error on ACTIVE -> FAILED direct jump")
	}

	// 合法路径: ACTIVE -> DEGRADED -> FAILING -> FAILED -> RECOVERING -> READY
	if err := r.TransitionTo(StateDegraded); err != nil {
		t.Fatalf("ACTIVE -> DEGRADED failed: %v", err)
	}
	if err := r.TransitionTo(StateFailing); err != nil {
		t.Fatalf("DEGRADED -> FAILING failed: %v", err)
	}
	if err := r.TransitionTo(StateFailed); err != nil {
		t.Fatalf("FAILING -> FAILED failed: %v", err)
	}
	if err := r.TransitionTo(StateRecovering); err != nil {
		t.Fatalf("FAILED -> RECOVERING failed: %v", err)
	}
	if err := r.TransitionTo(StateReady); err != nil {
		t.Fatalf("RECOVERING -> READY failed: %v", err)
	}
}

func TestScorerNormalAndPeak(t *testing.T) {
	s := NewScorer()

	mHighSpeed := &RouteMetrics{
		DownloadSpeed:    40 * 1024 * 1024, // 40 MB/s
		MinSpeed:         30 * 1024 * 1024,
		Stability:        0.95,
		PacketLoss:       0.01,
		Jitter:           2.0,
		RTT:              45.0,
		HandshakeSuccess: true,
	}

	mHighStability := &RouteMetrics{
		DownloadSpeed:    10 * 1024 * 1024, // 10 MB/s
		MinSpeed:         9 * 1024 * 1024,
		Stability:        0.99,
		PacketLoss:       0.0,
		Jitter:           1.0,
		RTT:              40.0,
		HandshakeSuccess: true,
	}

	scoreNormal1 := s.CalcInstantScore(mHighSpeed, false)
	scorePeak1 := s.CalcInstantScore(mHighSpeed, true)

	scoreNormal2 := s.CalcInstantScore(mHighStability, false)
	scorePeak2 := s.CalcInstantScore(mHighStability, true)

	if scoreNormal1 <= 0 || scorePeak1 <= 0 || scoreNormal2 <= 0 || scorePeak2 <= 0 {
		t.Fatal("scores should be positive")
	}

	// 验证握手失败时评分为 0
	mFail := &RouteMetrics{HandshakeSuccess: false}
	if s.CalcInstantScore(mFail, false) != 0 {
		t.Error("handshake failed should score 0")
	}
}

func TestHistoricalScoreSmoothing(t *testing.T) {
	s := NewScorer()
	m := &RouteMetrics{
		DownloadSpeed:    10 * 1024 * 1024,
		Stability:        0.9,
		HandshakeSuccess: true,
	}

	// 首次更新
	s.UpdateRouteScores(m, false)
	initialScore := m.Score
	if initialScore <= 0 {
		t.Fatalf("initial score should be > 0, got %f", initialScore)
	}

	// 偶尔一次超高虚高测速 (100MB/s)
	m.DownloadSpeed = 100 * 1024 * 1024
	s.UpdateRouteScores(m, false)

	// InstantScore 会迅速上升，但 Final Score 受平滑限制不会瞬间暴涨到 100
	if m.InstantScore <= initialScore {
		t.Errorf("instant score should rise: %f vs %f", m.InstantScore, initialScore)
	}
	if m.Score > m.InstantScore {
		t.Errorf("final score should be smoothed by history, got %f > instant %f", m.Score, m.InstantScore)
	}
}

func TestAntiFlappingCooldownAndThreshold(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:           true,
		CheckInterval:     1,
		SwitchThreshold:   10.0, // 门槛需相差 10 分
		SwitchCooldown:    2,    // 2 秒冷却
		MinimumStableTime: 0,    // 测试直接跳过稳定等待
		FailureThreshold:  3,
		RecoveryThreshold: 2,
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "Route 1", Address: "127.0.0.1", Port: 9191, Protocol: "socks5"},
			{ID: "r2", Name: "Route 2", Address: "127.0.0.1", Port: 9192, Protocol: "socks5"},
		},
	}

	switched := make(chan string, 10)
	c := NewRouteController(cfg, func(r *Route) {
		switched <- r.ID
	})

	_ = c.Start()
	defer c.Stop()

	// 初始应为 r1
	curr := c.GetCurrentRoute()
	if curr == nil || curr.ID != "r1" {
		t.Fatalf("initial route should be r1, got %v", curr)
	}

	// 上报 r1 分数 60，r2 分数 65（门槛差只有 5 < 10，不应切换）
	handshake := true
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", DownloadSpeed: 10 * 1024 * 1024, Stability: 0.8, HandshakeSuccess: &handshake},
		{ID: "r2", DownloadSpeed: 12 * 1024 * 1024, Stability: 0.82, HandshakeSuccess: &handshake},
	})

	time.Sleep(50 * time.Millisecond)
	if c.GetCurrentRoute().ID != "r1" {
		t.Fatal("should not switch because score difference < threshold (10.0)")
	}

	// 上报 r2 分数 90（门槛差 > 10，但处于冷却期 2s 内，不应切换）
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r2", DownloadSpeed: 50 * 1024 * 1024, Stability: 0.99, PacketLoss: 0, Jitter: 1, HandshakeSuccess: &handshake},
	})
	time.Sleep(50 * time.Millisecond)
	if c.GetCurrentRoute().ID != "r1" {
		t.Fatal("should not switch during cooldown")
	}

	// 等待冷却期过去 (2.2s)
	time.Sleep(2200 * time.Millisecond)
	c.Evaluate()
	time.Sleep(50 * time.Millisecond)

	if c.GetCurrentRoute().ID != "r2" {
		t.Fatalf("should switch to r2 after cooldown, current: %s", c.GetCurrentRoute().ID)
	}
}

func TestWarmStandbyManagement(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:      true,
		StandbyCount: 2, // 保持 2 条 Standby
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
			{ID: "r3", Name: "R3", Address: "127.0.0.1", Port: 1003, Protocol: "socks5"},
			{ID: "r4", Name: "R4", Address: "127.0.0.1", Port: 1004, Protocol: "socks5"},
		},
	}

	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	// r1 为 active，其余为 standby 或 ready
	standbys := c.GetStandbyRoutes()
	if len(standbys) != 2 {
		t.Fatalf("expected 2 standbys, got %d", len(standbys))
	}
}

func TestConcurrentMetricUpdateAndSwitch(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:        true,
		SwitchCooldown: 0, // 测试并发无冷却
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 2001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 2002, Protocol: "socks5"},
		},
	}

	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	var wg sync.WaitGroup
	handshake := true

	// 并发上报指标
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c.ReportMetrics([]RouteMetricReport{
				{ID: "r1", DownloadSpeed: float64(idx * 1024 * 1024), HandshakeSuccess: &handshake},
				{ID: "r2", DownloadSpeed: float64((20 - idx) * 1024 * 1024), HandshakeSuccess: &handshake},
			})
		}(i)
	}

	// 并发手动切线路
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_ = c.SwitchTo("r1", true)
			} else {
				_ = c.SwitchTo("r2", true)
			}
		}(i)
	}

	wg.Wait()
	if c.GetCurrentRoute() == nil {
		t.Fatal("current route should not be nil")
	}
}
