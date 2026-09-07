package controller

import (
	"net"
	"strconv"
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
		MinimumStableTime: -1,   // 测试直接跳过稳定等待
		FailureThreshold:  3,
		RecoveryThreshold: 2,
		HistoryFile:       "none",
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
		HistoryFile:  "none",
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
		SwitchCooldown: -1, // 测试并发无冷却
		HistoryFile:    "none",
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

func TestProbe_SuccessAndFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 16)
				n, err := conn.Read(buf)
				if err == nil && n >= 3 && buf[0] == 0x05 {
					_, _ = conn.Write([]byte{0x05, 0x00})
				}
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	p := NewProber(1*time.Second, 2)
	rSuccess := NewRoute("r_ok", "Route OK", host, port, "socks5", "goway")
	res := p.ProbeRoute(rSuccess)
	if !res.Success {
		t.Fatalf("expected probe success on local mock SOCKS5, got err: %v", res.Err)
	}
	if res.RTT < 0 {
		t.Fatalf("expected non-negative RTT, got %f", res.RTT)
	}

	// 探测不可达端口
	rFail := NewRoute("r_fail", "Route Fail", "127.0.0.1", 59199, "socks5", "goway")
	resFail := p.ProbeRoute(rFail)
	if resFail.Success {
		t.Fatal("expected probe failure on closed port")
	}
	if resFail.Err == nil {
		t.Fatal("expected probe error on closed port")
	}
}

func TestReport_MissingHandshake_NoManufacturedSuccess(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:     true,
		HistoryFile: "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	// 上报缺失握手，且没有有效测速与延迟数据
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: nil, DownloadSpeed: 0, RTT: 0, SingleSpeed: 0},
	})

	r := c.GetCurrentRoute()
	if r == nil {
		t.Fatal("current route should not be nil")
	}
	if r.Metrics.ProbeSuccess {
		t.Fatal("ProbeSuccess should be false when metrics are completely missing")
	}
	if r.Metrics.SuccessCount != 0 {
		t.Fatalf("SuccessCount should not increment on missing metrics, got %d", r.Metrics.SuccessCount)
	}
	if r.Metrics.FailureCount != 0 {
		t.Fatalf("FailureCount should not increment on missing metrics, got %d", r.Metrics.FailureCount)
	}
}

func TestFailureAndSuccessCount_MutualExclusion(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:     true,
		HistoryFile: "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	bFalse := false
	bTrue := true

	// 1. 失败上报
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bFalse},
	})
	m := c.GetCurrentRoute().Metrics
	if m.FailureCount != 1 || m.SuccessCount != 0 {
		t.Fatalf("expected FailureCount=1, SuccessCount=0, got F=%d, S=%d", m.FailureCount, m.SuccessCount)
	}

	// 2. 连续第二次失败
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bFalse},
	})
	m = c.GetCurrentRoute().Metrics
	if m.FailureCount != 2 || m.SuccessCount != 0 {
		t.Fatalf("expected FailureCount=2, SuccessCount=0, got F=%d, S=%d", m.FailureCount, m.SuccessCount)
	}

	// 3. 成功上报 -> FailureCount 清零，SuccessCount 递增
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bTrue, DownloadSpeed: 10 * 1024 * 1024, RTT: 30},
	})
	m = c.GetCurrentRoute().Metrics
	if m.FailureCount != 0 || m.SuccessCount != 1 {
		t.Fatalf("expected FailureCount=0, SuccessCount=1 after success, got F=%d, S=%d", m.FailureCount, m.SuccessCount)
	}
}

func TestDegraded_RealTimeDuration(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:     true,
		HistoryFile: "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	bTrue := true

	// 1. 第一次劣变上报 (丢包 20% > 15%)
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", PacketLoss: 0.20, HandshakeSuccess: &bTrue, RTT: 50, DownloadSpeed: 5 * 1024 * 1024},
	})

	r := c.GetCurrentRoute()
	if r.State != StateActive {
		t.Fatalf("should not degrade immediately on first fluctuation, state: %s", r.State)
	}

	c.routesMu.RLock()
	routeObj := c.routes["r1"]
	c.routesMu.RUnlock()

	// 模拟劣变持续时间已经超过 20 秒
	routeObj.SetDegradedSince(time.Now().Add(-25 * time.Second))

	// 第二次劣变上报 -> 达到持续时间，正式进入 DEGRADED
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", PacketLoss: 0.20, HandshakeSuccess: &bTrue, RTT: 50, DownloadSpeed: 5 * 1024 * 1024},
	})

	r = c.GetCurrentRoute()
	if r.State != StateDegraded {
		t.Fatalf("expected DEGRADED after >20s sustained degradation, got %s", r.State)
	}

	// 恢复正常
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", PacketLoss: 0.0, Jitter: 2.0, HandshakeSuccess: &bTrue, RTT: 30, DownloadSpeed: 15 * 1024 * 1024},
	})
	r = c.GetCurrentRoute()
	if r.State != StateActive {
		t.Fatalf("expected recovery to ACTIVE, got %s", r.State)
	}
	if !routeObj.GetDegradedSince().IsZero() {
		t.Fatal("degradedSince should be reset to zero on recovery")
	}
}

func TestEmergencyFailover_BypassesCooldown(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:           true,
		SwitchCooldown:    60, // 60秒冷却
		FailureThreshold:  3,
		MinimumStableTime: -1,
		HistoryFile:       "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	bFalse := false
	bTrue := true

	// r2 准备就绪且健康
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r2", HandshakeSuccess: &bTrue, DownloadSpeed: 20 * 1024 * 1024, RTT: 25},
	})

	// r1 发生连续 3 次严重故障 (达到 FailureThreshold)
	for i := 0; i < 3; i++ {
		c.ReportMetrics([]RouteMetricReport{
			{ID: "r1", HandshakeSuccess: &bFalse},
		})
	}

	// 验证紧急故障转移：即使在 60s 冷却期内，也必须立即切换至备选 r2
	curr := c.GetCurrentRoute()
	if curr == nil || curr.ID != "r2" {
		t.Fatalf("emergency failover should immediately switch to r2, got %v", curr)
	}
	if curr.State != StateActive {
		t.Fatalf("r2 should be ACTIVE, got %s", curr.State)
	}
}

func TestRecovery_ThresholdGuards(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:           true,
		RecoveryThreshold: 3,
		FailureThreshold:  2,
		HistoryFile:       "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	bFalse := false
	bTrue := true

	// 让 r1 彻底失败变成 FAILED
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bFalse},
	})
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bFalse},
	})

	c.routesMu.RLock()
	r1 := c.routes["r1"]
	c.routesMu.RUnlock()

	if r1.GetState() != StateFailed {
		t.Fatalf("expected r1 to be FAILED, got %s", r1.GetState())
	}

	// 第 1 次成功探测 -> 进入 RECOVERING
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bTrue, DownloadSpeed: 5 * 1024 * 1024, RTT: 50},
	})
	if r1.GetState() != StateRecovering {
		t.Fatalf("expected RECOVERING after 1st success, got %s", r1.GetState())
	}

	// 第 2 次成功探测 -> 仍为 RECOVERING (需 3 次)
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bTrue, DownloadSpeed: 5 * 1024 * 1024, RTT: 50},
	})
	if r1.GetState() != StateRecovering {
		t.Fatalf("expected still RECOVERING after 2nd success, got %s", r1.GetState())
	}

	// 第 3 次成功探测 -> 达到 RecoveryThreshold，恢复到 READY
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bTrue, DownloadSpeed: 5 * 1024 * 1024, RTT: 50},
	})
	if r1.GetState() != StateReady && r1.GetState() != StateStandby {
		t.Fatalf("expected READY or STANDBY after 3 successes, got %s", r1.GetState())
	}
}

func TestCandidate_StableTimeResetOnDrop(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:           true,
		SwitchThreshold:   10.0,
		MinimumStableTime: 2, // 需要稳定 2 秒
		SwitchCooldown:    -1,
		HistoryFile:       "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	bTrue := true

	// r1 初始 50 分
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", DownloadSpeed: 5 * 1024 * 1024, Stability: 0.8, HandshakeSuccess: &bTrue},
	})

	// r2 突然出现 85 分 (高于 r1 门槛 10 分) -> 启动稳定计时
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r2", DownloadSpeed: 30 * 1024 * 1024, Stability: 0.9, HandshakeSuccess: &bTrue},
	})

	c.switchMu.Lock()
	candID := c.candidateID
	c.switchMu.Unlock()
	if candID != "r2" {
		t.Fatalf("candidate should be r2, got %s", candID)
	}

	// r2 分数突然回落到 52 分 (<= 50 + 10) -> 必须清空候选与稳定时间
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r2", DownloadSpeed: 5 * 1024 * 1024, Stability: 0.8, HandshakeSuccess: &bTrue},
	})

	c.switchMu.Lock()
	candID = c.candidateID
	c.switchMu.Unlock()
	if candID != "" {
		t.Fatalf("candidate should be reset to empty when score drops, got %s", candID)
	}

	// 确认未发生错误切换
	if c.GetCurrentRoute().ID != "r1" {
		t.Fatalf("current should still be r1, got %s", c.GetCurrentRoute().ID)
	}
}

func TestController_DoubleStop_NoPanic(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:     false,
		HistoryFile: "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()

	// 重复调用 Stop 不应发生 panic
	c.Stop()
	c.Stop()
	c.Stop()
}

func TestActiveStandby_StrictExclusivity(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:      true,
		StandbyCount: 2,
		HistoryFile:  "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
			{ID: "r3", Name: "R3", Address: "127.0.0.1", Port: 1003, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	// 切换到 r2
	_ = c.SwitchTo("r2", true)

	// 统计系统中所有状态为 ACTIVE 的线路数量
	activeCount := 0
	routes := c.GetRoutes()
	for i := range routes {
		if routes[i].State == StateActive {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("expected exactly 1 ACTIVE route, found %d", activeCount)
	}

	if c.GetCurrentRoute().ID != "r2" {
		t.Fatalf("active route should be r2, got %s", c.GetCurrentRoute().ID)
	}
}

func TestSwitchTo_RejectFailedRoute(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:     true,
		HistoryFile: "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	// 1. 初始 r1 为 ACTIVE
	if c.GetCurrentRoute().ID != "r1" {
		t.Fatalf("expected r1 to be active, got %v", c.GetCurrentRoute())
	}

	// 2. 将 r2 推入 FAILED
	c.routesMu.RLock()
	r2 := c.routes["r2"]
	c.routesMu.RUnlock()

	_ = r2.TransitionTo(StateDegraded)
	_ = r2.TransitionTo(StateFailing)
	if err := r2.TransitionTo(StateFailed); err != nil {
		t.Fatalf("failed to push r2 to FAILED: %v", err)
	}
	if r2.GetState() != StateFailed {
		t.Fatalf("r2 state should be FAILED, got %s", r2.GetState())
	}

	// 3. 初始验证系统活跃唯一性
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("active consistency failed: %v", err)
	}

	// 4. 调用 SwitchTo("r2", true)
	err := c.SwitchTo("r2", true)

	// 5. 必须返回 error
	if err == nil {
		t.Fatal("expected SwitchTo failed route to return error, got nil")
	}

	// 6. 当前 activeRoute 仍然是 r1
	curr := c.GetCurrentRoute()
	if curr == nil || curr.ID != "r1" {
		t.Fatalf("current active route should still be r1, got %v", curr)
	}
	if curr.State != StateActive {
		t.Fatalf("r1 state should remain ACTIVE, got %s", curr.State)
	}

	// 7. r2 仍然是 FAILED
	if r2.GetState() != StateFailed {
		t.Fatalf("r2 state should remain FAILED, got %s", r2.GetState())
	}

	// 8. 系统中 ACTIVE 数量仍然严格为 1
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("active consistency failed after rejected switch: %v", err)
	}
}

func TestSwitchTo_RejectRecoveringRoute(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:     true,
		HistoryFile: "none",
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
		},
	}
	c := NewRouteController(cfg, nil)
	_ = c.Start()
	defer c.Stop()

	// r2 推入 RECOVERING
	c.routesMu.RLock()
	r2 := c.routes["r2"]
	c.routesMu.RUnlock()

	_ = r2.TransitionTo(StateDegraded)
	_ = r2.TransitionTo(StateFailing)
	_ = r2.TransitionTo(StateFailed)
	if err := r2.TransitionTo(StateRecovering); err != nil {
		t.Fatalf("failed to push r2 to RECOVERING: %v", err)
	}

	// 试图将 RECOVERING 线路切换为 ACTIVE -> 必须拒绝并返回 error
	err := c.SwitchTo("r2", true)
	if err == nil {
		t.Fatal("expected SwitchTo recovering route to return error, got nil")
	}

	// activeRoute 仍然是 r1，且 r2 依然是 RECOVERING
	if c.GetCurrentRoute().ID != "r1" {
		t.Fatalf("current active route should remain r1, got %s", c.GetCurrentRoute().ID)
	}
	if r2.GetState() != StateRecovering {
		t.Fatalf("r2 state should remain RECOVERING, got %s", r2.GetState())
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("active consistency failed: %v", err)
	}
}

func TestActive_StrictUniqueness_AllScenarios(t *testing.T) {
	cfg := config.AutomaticRouteConfig{
		Enabled:           true,
		HistoryFile:       "none",
		MinimumStableTime: -1,
		SwitchCooldown:    -1,
		FailureThreshold:  3,
		Routes: []config.RouteConfig{
			{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 1001, Protocol: "socks5"},
			{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 1002, Protocol: "socks5"},
		},
	}

	c := NewRouteController(cfg, nil)

	// Scenario 1: 未 Start 之前
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed before start: %v", err)
	}

	// Scenario 2: Start 初始化
	if err := c.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer c.Stop()

	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after start: %v", err)
	}
	if c.GetCurrentRoute().ID != "r1" || c.GetCurrentRoute().State != StateActive {
		t.Fatalf("expected r1 ACTIVE after start, got %v", c.GetCurrentRoute())
	}

	// Scenario 3: 正常 SwitchTo
	if err := c.SwitchTo("r2", true); err != nil {
		t.Fatalf("normal SwitchTo r2 failed: %v", err)
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after normal switch: %v", err)
	}
	if c.GetCurrentRoute().ID != "r2" || c.GetCurrentRoute().State != StateActive {
		t.Fatalf("expected r2 ACTIVE, got %v", c.GetCurrentRoute())
	}

	// Scenario 4: 非法 SwitchTo (目标处于 FAILED 或 RECOVERING)
	c.routesMu.RLock()
	r1 := c.routes["r1"]
	c.routesMu.RUnlock()
	_ = r1.TransitionTo(StateDegraded)
	_ = r1.TransitionTo(StateFailing)
	_ = r1.TransitionTo(StateFailed)

	if err := c.SwitchTo("r1", true); err == nil {
		t.Fatal("expected SwitchTo FAILED route to fail")
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after illegal switch to FAILED: %v", err)
	}

	_ = r1.TransitionTo(StateRecovering)
	if err := c.SwitchTo("r1", true); err == nil {
		t.Fatal("expected SwitchTo RECOVERING route to fail")
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after illegal switch to RECOVERING: %v", err)
	}

	// Scenario 5: RegisterRoute
	r3 := NewRoute("r3", "R3", "127.0.0.1", 1003, "socks5", "goway")
	if err := c.RegisterRoute(r3); err != nil {
		t.Fatalf("RegisterRoute r3 failed: %v", err)
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after RegisterRoute: %v", err)
	}

	// 注册时恶意带有 StateActive 属性 -> 必须被平稳规范化为 READY
	r4 := NewRoute("r4", "R4", "127.0.0.1", 1004, "socks5", "goway")
	r4.State = StateActive
	if err := c.RegisterRoute(r4); err != nil {
		t.Fatalf("RegisterRoute r4 failed: %v", err)
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after RegisterRoute with fake active: %v", err)
	}

	// Scenario 6: UnregisterRoute
	if err := c.UnregisterRoute("r3"); err != nil {
		t.Fatalf("UnregisterRoute r3 failed: %v", err)
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after UnregisterRoute: %v", err)
	}

	// 严禁反注册当前 ACTIVE 线路
	if err := c.UnregisterRoute(c.GetCurrentRoute().ID); err == nil {
		t.Fatal("expected error on unregistering ACTIVE route")
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after rejected unregister: %v", err)
	}

	// Scenario 7: Emergency Failover
	// 将 r1 恢复至 READY
	_ = r1.TransitionTo(StateReady)
	bTrue := true
	bFalse := false
	c.ReportMetrics([]RouteMetricReport{
		{ID: "r1", HandshakeSuccess: &bTrue, DownloadSpeed: 20 * 1024 * 1024, RTT: 20},
	})
	// 当前 active (r2) 连续失败 3 次触发紧急转移
	for i := 0; i < 3; i++ {
		c.ReportMetrics([]RouteMetricReport{
			{ID: "r2", HandshakeSuccess: &bFalse},
		})
	}
	if c.GetCurrentRoute().ID != "r1" {
		t.Fatalf("expected emergency failover to r1, got %s", c.GetCurrentRoute().ID)
	}
	if err := c.CheckActiveConsistency(); err != nil {
		t.Fatalf("consistency failed after emergency failover: %v", err)
	}
}
