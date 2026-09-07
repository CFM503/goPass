package controller

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

// RouteMetricReport 外部 CFST 或测试工具上报的 JSON 数据模型
type RouteMetricReport struct {
	ID               string   `json:"id"`
	Name             string   `json:"name,omitempty"`
	Address          string   `json:"address"`
	Port             int      `json:"port"`
	Protocol         string   `json:"protocol,omitempty"` // "socks5" | "http"
	Type             string   `json:"type,omitempty"`
	RTT              float64  `json:"rtt"`
	PacketLoss       float64  `json:"packet_loss"`
	Jitter           float64  `json:"jitter"`
	DownloadSpeed    float64  `json:"download_speed"`
	SingleSpeed      float64  `json:"single_speed"`
	MinSpeed         float64  `json:"min_speed"`
	Stability        float64  `json:"stability"`
	LoadLatency      float64  `json:"load_latency"`
	HandshakeSuccess *bool    `json:"handshake_success,omitempty"`
}

// RouteController 动态线路调度中心
type RouteController struct {
	cfg         config.AutomaticRouteConfig
	cfgMu       sync.RWMutex
	routes      map[string]*Route
	activeRoute *Route
	standby     []*Route
	routesMu    sync.RWMutex

	scorer      *Scorer
	peakTracker *PeakHourTracker
	prober      *Prober
	storage     *HistoryStorage

	onSwitch    func(r *Route)
	autoEnabled atomic.Bool

	switchMu    sync.Mutex
	lastSwitch  time.Time

	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// NewRouteController 创建调度中心
func NewRouteController(cfg config.AutomaticRouteConfig, onSwitch func(r *Route)) *RouteController {
	c := &RouteController{
		cfg:         cfg,
		routes:      make(map[string]*Route),
		scorer:      NewScorer(),
		peakTracker: NewPeakHourTracker(),
		prober:      NewProber(2*time.Second, cfg.MaxProbeConcurrency),
		storage:     NewHistoryStorage(cfg.HistoryFile),
		onSwitch:    onSwitch,
		stopCh:      make(chan struct{}),
	}
	c.autoEnabled.Store(cfg.Enabled)

	// 载入预置线路
	for _, rc := range cfg.Routes {
		r := NewRoute(rc.ID, rc.Name, rc.Address, rc.Port, rc.Protocol, rc.Type)
		r.State = StateReady
		c.routes[r.ID] = r
	}

	// 尝试恢复历史持久化数据
	if hist, err := c.storage.Load(); err == nil && hist != nil {
		c.peakTracker.LoadStats(hist.HourlyStats)
		for _, snap := range hist.Routes {
			if existing, ok := c.routes[snap.ID]; ok {
				existing.Metrics = snap.Metrics
			}
		}
		log.Printf("[RouteController] 成功载入历史表现数据 (共 %d 条线路, 更新于 %s)", len(hist.Routes), hist.UpdatedAt.Format("15:04:05"))
	}

	return c
}

// Start 启动后台探测与调度循环
func (c *RouteController) Start() error {
	c.routesMu.Lock()
	// 若尚未有 Active 线路，选出第一条就绪线路设为 Active
	if c.activeRoute == nil && len(c.routes) > 0 {
		for _, r := range c.routes {
			if r.State == StateReady || r.State == StateStandby {
				_ = r.TransitionTo(StateActive)
				c.activeRoute = r
				c.lastSwitch = time.Now()
				log.Printf("[RouteController] 初始化激活首选线路: [%s] %s (%s:%d)", r.ID, r.Name, r.Address, r.Port)
				if c.autoEnabled.Load() && c.onSwitch != nil {
					c.onSwitch(r)
				}
				break
			}
		}
	}
	c.updateStandbyListLocked()
	c.routesMu.Unlock()

	c.wg.Add(1)
	go c.tickLoop()
	log.Printf("[RouteController] 动态线路调度引擎已启动 (Auto=%v, Check=%ds, Cooldown=%ds, Threshold=%.1f)",
		c.autoEnabled.Load(), c.cfg.CheckInterval, c.cfg.SwitchCooldown, c.cfg.SwitchThreshold)
	return nil
}

// Stop 停止调度引擎并优雅持久化
func (c *RouteController) Stop() {
	select {
	case <-c.stopCh:
		return
	default:
		close(c.stopCh)
	}
	c.wg.Wait()

	// 退出前同步持久化
	c.routesMu.RLock()
	var list []*Route
	for _, r := range c.routes {
		list = append(list, r)
	}
	hourly := c.peakTracker.GetAllStats()
	c.routesMu.RUnlock()

	c.storage.SaveAsync(list, hourly)
	log.Println("[RouteController] 动态线路调度引擎已停止")
}

// EnableAuto 启用自动调度
func (c *RouteController) EnableAuto() {
	c.autoEnabled.Store(true)
	log.Println("[RouteController] 自动线路调度已启用")
	c.Evaluate()
}

// DisableAuto 禁用自动调度
func (c *RouteController) DisableAuto() {
	c.autoEnabled.Store(false)
	log.Println("[RouteController] 自动线路调度已禁用 (保持当前线路)")
}

// IsAutoEnabled 是否处于自动调度模式
func (c *RouteController) IsAutoEnabled() bool {
	return c.autoEnabled.Load()
}

// RegisterRoute 动态注册或更新线路
func (c *RouteController) RegisterRoute(r *Route) error {
	if r.ID == "" {
		return fmt.Errorf("线路 ID 不能为空")
	}
	c.routesMu.Lock()
	defer c.routesMu.Unlock()

	existing, ok := c.routes[r.ID]
	if ok {
		existing.mu.Lock()
		existing.Name = r.Name
		existing.Address = r.Address
		existing.Port = r.Port
		existing.Protocol = r.Protocol
		existing.Type = r.Type
		existing.mu.Unlock()
	} else {
		if r.State == StateUnknown {
			r.State = StateReady
		}
		c.routes[r.ID] = r
	}
	c.updateStandbyListLocked()
	return nil
}

// UnregisterRoute 删除线路
func (c *RouteController) UnregisterRoute(id string) error {
	c.routesMu.Lock()
	defer c.routesMu.Unlock()

	if c.activeRoute != nil && c.activeRoute.ID == id {
		return fmt.Errorf("无法删除当前活跃的线路: %s", id)
	}
	delete(c.routes, id)
	c.updateStandbyListLocked()
	return nil
}

// GetRoutes 获取所有线路快照
func (c *RouteController) GetRoutes() []Route {
	c.routesMu.RLock()
	defer c.routesMu.RUnlock()

	result := make([]Route, 0, len(c.routes))
	for _, r := range c.routes {
		result = append(result, r.Snapshot())
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Metrics.Score > result[j].Metrics.Score
	})
	return result
}

// GetCurrentRoute 获取当前活动线路快照
func (c *RouteController) GetCurrentRoute() *Route {
	c.routesMu.RLock()
	defer c.routesMu.RUnlock()

	if c.activeRoute == nil {
		return nil
	}
	snap := c.activeRoute.Snapshot()
	return &snap
}

// GetStandbyRoutes 获取备用线路快照列表
func (c *RouteController) GetStandbyRoutes() []Route {
	c.routesMu.RLock()
	defer c.routesMu.RUnlock()

	result := make([]Route, 0, len(c.standby))
	for _, r := range c.standby {
		result = append(result, r.Snapshot())
	}
	return result
}

// GetMetrics 获取所有线路的实时指标快照
func (c *RouteController) GetMetrics() map[string]RouteMetrics {
	c.routesMu.RLock()
	defer c.routesMu.RUnlock()

	res := make(map[string]RouteMetrics, len(c.routes))
	for id, r := range c.routes {
		snap := r.Snapshot()
		res[id] = snap.Metrics
	}
	return res
}

// SwitchTo 手动或自动切换至指定线路
func (c *RouteController) SwitchTo(targetID string, manual bool) error {
	c.switchMu.Lock()
	defer c.switchMu.Unlock()

	c.routesMu.Lock()
	target, ok := c.routes[targetID]
	if !ok {
		c.routesMu.Unlock()
		return fmt.Errorf("目标线路未找到: %s", targetID)
	}

	current := c.activeRoute
	if current != nil && current.ID == targetID {
		c.routesMu.Unlock()
		return nil // 已经是当前线路
	}

	// 手动切换无视冷却和门槛；自动切换在 Evaluate 中已校验
	now := time.Now()
	if !manual {
		cooldown := time.Duration(c.cfg.SwitchCooldown) * time.Second
		if current != nil && current.GetState() == StateActive && now.Sub(c.lastSwitch) < cooldown {
			c.routesMu.Unlock()
			return fmt.Errorf("处于切换冷却期中 (已过 %v, 需 %v)", now.Sub(c.lastSwitch).Round(time.Second), cooldown)
		}
	}

	// 状态机流转
	if current != nil {
		if current.GetState() == StateActive {
			_ = current.TransitionTo(StateStandby)
		}
	}

	if target.GetState() != StateActive {
		_ = target.TransitionTo(StateActive)
	}

	c.activeRoute = target
	c.lastSwitch = now
	c.updateStandbyListLocked()
	c.routesMu.Unlock()

	log.Printf("[RouteController] 🚀 线路已切换为: [%s] %s (%s:%d), 综合分: %.1f",
		target.ID, target.Name, target.Address, target.Port, target.Metrics.Score)

	// 回调 GoPass Engine 触发真正的 UpdateUpstream (新连接使用新线路，旧连接不断)
	if c.onSwitch != nil {
		c.onSwitch(target)
	}
	return nil
}

// ReportMetrics 接收来自 CFST 或外部测试器的 RouteMetrics 数据
func (c *RouteController) ReportMetrics(reports []RouteMetricReport) {
	now := time.Now()
	isPeak := c.peakTracker.IsPeakHour(now, c.cfg.PeakMode, c.cfg.PeakStartHour, c.cfg.PeakEndHour)

	for _, rep := range reports {
		if rep.ID == "" && rep.Address != "" {
			rep.ID = fmt.Sprintf("%s:%d", rep.Address, rep.Port)
		}
		if rep.ID == "" {
			continue
		}

		c.routesMu.Lock()
		r, ok := c.routes[rep.ID]
		if !ok {
			// 自动注册新发现的线路
			name := rep.Name
			if name == "" {
				name = rep.ID
			}
			r = NewRoute(rep.ID, name, rep.Address, rep.Port, rep.Protocol, rep.Type)
			r.State = StateReady
			c.routes[rep.ID] = r
		}
		c.routesMu.Unlock()

		// 更新指标与历史加权打分
		r.UpdateMetrics(func(m *RouteMetrics) {
			m.RTT = rep.RTT
			m.PacketLoss = rep.PacketLoss
			m.Jitter = rep.Jitter
			m.DownloadSpeed = rep.DownloadSpeed
			if rep.SingleSpeed > 0 {
				m.SingleSpeed = rep.SingleSpeed
			}
			if rep.MinSpeed > 0 {
				m.MinSpeed = rep.MinSpeed
			}
			if rep.Stability > 0 {
				m.Stability = rep.Stability
			}
			m.LoadLatency = rep.LoadLatency
			if rep.HandshakeSuccess != nil {
				m.HandshakeSuccess = *rep.HandshakeSuccess
			} else {
				m.HandshakeSuccess = true
			}

			if m.HandshakeSuccess {
				m.SuccessCount++
				m.FailureCount = 0
			} else {
				m.FailureCount++
				m.SuccessCount = 0
			}

			// 计分
			c.scorer.UpdateRouteScores(m, isPeak)
		})

		// 记录时段样本
		rSnap := r.Snapshot()
		c.peakTracker.RecordSample(r.ID, now, &rSnap.Metrics)

		// 状态机感知：
		// 1. 如果连续失败达到阈值 -> FAILED
		if rSnap.Metrics.FailureCount >= c.cfg.FailureThreshold {
			if rSnap.State == StateActive {
				_ = r.TransitionTo(StateDegraded)
				_ = r.TransitionTo(StateFailing)
				_ = r.TransitionTo(StateFailed)
			} else if rSnap.State != StateFailed && rSnap.State != StateRecovering {
				_ = r.TransitionTo(StateFailed)
			}
		} else if rSnap.State == StateFailed && rSnap.Metrics.HandshakeSuccess {
			_ = r.TransitionTo(StateRecovering)
		} else if rSnap.State == StateRecovering && rSnap.Metrics.SuccessCount >= c.cfg.RecoveryThreshold {
			_ = r.TransitionTo(StateReady)
		} else if rSnap.State == StateActive {
			// 视频/长连接特殊处理：如果只是瞬时速度下降且丢包不高，不轻易进 DEGRADED
			if rSnap.Metrics.PacketLoss > 0.15 || rSnap.Metrics.Jitter > 60 {
				r.degradedStreak += 5 * time.Second
				if r.degradedStreak >= 20*time.Second {
					_ = r.TransitionTo(StateDegraded)
				}
			} else {
				r.degradedStreak = 0
			}
		}
	}

	c.routesMu.Lock()
	c.updateStandbyListLocked()
	c.routesMu.Unlock()

	// 评估是否需要切换
	c.Evaluate()
}

// Evaluate 线路质量评估与调度决策
func (c *RouteController) Evaluate() {
	if !c.autoEnabled.Load() {
		return
	}

	c.routesMu.RLock()
	current := c.activeRoute
	var candidates []*Route
	for _, r := range c.routes {
		if current != nil && r.ID == current.ID {
			continue
		}
		st := r.GetState()
		if st == StateReady || st == StateStandby {
			candidates = append(candidates, r)
		}
	}
	c.routesMu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	// 按评分从高到低排序候选线路
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Metrics.Score > candidates[j].Metrics.Score
	})
	bestCandidate := candidates[0]

	now := time.Now()

	// Case 1: 当前没有活跃线路，或当前活跃线路已 FAILED / FAILING
	if current == nil || current.GetState() == StateFailed || current.GetState() == StateFailing {
		log.Printf("[RouteController] 当前线路异常 (%v)，紧急晋升最优候选: [%s] %.1f分",
			current, bestCandidate.ID, bestCandidate.Metrics.Score)
		_ = c.SwitchTo(bestCandidate.ID, false)
		return
	}

	// Case 2: 当前线路处于正常 ACTIVE 或 DEGRADED
	// 检查切换冷却时间
	cooldown := time.Duration(c.cfg.SwitchCooldown) * time.Second
	if now.Sub(c.lastSwitch) < cooldown {
		return
	}

	// 检查新线路分值门槛：NewScore > CurrentScore + Threshold
	currentScore := current.Metrics.Score
	if bestCandidate.Metrics.Score <= currentScore+c.cfg.SwitchThreshold {
		bestCandidate.firstHighAt = time.Time{} // 重置稳定计时
		return
	}

	// 检查候选线路持续稳定时间 MinimumStableTime
	if bestCandidate.firstHighAt.IsZero() {
		bestCandidate.firstHighAt = now
		return
	}
	stableTime := time.Duration(c.cfg.MinimumStableTime) * time.Second
	if now.Sub(bestCandidate.firstHighAt) < stableTime {
		// 稳定时间尚未满足，继续观察
		return
	}

	// 满足防抖与抗劣变条件，执行平滑切换
	log.Printf("[RouteController] 满足切换条件: 候选 [%s](%.1f分) 优于当前 [%s](%.1f分) 超过门槛 %.1f 且持续稳定 %v",
		bestCandidate.ID, bestCandidate.Metrics.Score, current.ID, currentScore, c.cfg.SwitchThreshold, stableTime)
	_ = c.SwitchTo(bestCandidate.ID, false)
}

// updateStandbyListLocked 维护 Warm Standby 列表 (取除 Active 外分值最高的前 N 条线路)
func (c *RouteController) updateStandbyListLocked() {
	var list []*Route
	for _, r := range c.routes {
		if c.activeRoute != nil && r.ID == c.activeRoute.ID {
			continue
		}
		st := r.GetState()
		if st == StateReady || st == StateStandby {
			list = append(list, r)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Metrics.Score > list[j].Metrics.Score
	})

	maxCount := c.cfg.StandbyCount
	if maxCount <= 0 {
		maxCount = 3
	}
	if len(list) > maxCount {
		list = list[:maxCount]
	}

	// 将入选的标记为 STANDBY，其余保持 READY
	standbySet := make(map[string]bool)
	for _, r := range list {
		standbySet[r.ID] = true
		if r.GetState() == StateReady {
			_ = r.TransitionTo(StateStandby)
		}
	}
	for _, r := range c.routes {
		if c.activeRoute != nil && r.ID == c.activeRoute.ID {
			continue
		}
		if !standbySet[r.ID] && r.GetState() == StateStandby {
			_ = r.TransitionTo(StateReady)
		}
	}

	c.standby = list
}

// tickLoop 运行后台探测与持久化计时器
func (c *RouteController) tickLoop() {
	defer c.wg.Done()

	activeInterval := time.Duration(c.cfg.CheckInterval) * time.Second
	if activeInterval <= 0 {
		activeInterval = 5 * time.Second
	}
	standbyInterval := time.Duration(c.cfg.StandbyCheckInterval) * time.Second
	if standbyInterval <= 0 {
		standbyInterval = 30 * time.Second
	}
	recoverInterval := time.Duration(c.cfg.RecoverCheckInterval) * time.Second
	if recoverInterval <= 0 {
		recoverInterval = 120 * time.Second
	}
	saveInterval := time.Duration(c.cfg.HistorySaveInterval) * time.Second
	if saveInterval <= 0 {
		saveInterval = 300 * time.Second
	}

	activeTicker := time.NewTicker(activeInterval)
	standbyTicker := time.NewTicker(standbyInterval)
	recoverTicker := time.NewTicker(recoverInterval)
	saveTicker := time.NewTicker(saveInterval)

	defer activeTicker.Stop()
	defer standbyTicker.Stop()
	defer recoverTicker.Stop()
	defer saveTicker.Stop()

	for {
		select {
		case <-c.stopCh:
			return

		case <-activeTicker.C:
			c.probeActive()

		case <-standbyTicker.C:
			c.probeStandbys()

		case <-recoverTicker.C:
			c.probeFailed()

		case <-saveTicker.C:
			c.routesMu.RLock()
			var list []*Route
			for _, r := range c.routes {
				list = append(list, r)
			}
			hourly := c.peakTracker.GetAllStats()
			c.routesMu.RUnlock()
			c.storage.SaveAsync(list, hourly)
		}
	}
}

// probeActive 高频探测当前活跃线路
func (c *RouteController) probeActive() {
	c.routesMu.RLock()
	active := c.activeRoute
	c.routesMu.RUnlock()

	if active == nil {
		return
	}

	res := c.prober.ProbeRoute(active)
	now := time.Now()
	isPeak := c.peakTracker.IsPeakHour(now, c.cfg.PeakMode, c.cfg.PeakStartHour, c.cfg.PeakEndHour)

	active.UpdateMetrics(func(m *RouteMetrics) {
		m.HandshakeSuccess = res.Success
		if res.Success {
			m.RTT = res.RTT
			m.FailureCount = 0
			m.SuccessCount++
		} else {
			m.FailureCount++
			m.SuccessCount = 0
		}
		c.scorer.UpdateRouteScores(m, isPeak)
	})

	if !res.Success {
		failCount := active.Metrics.FailureCount
		log.Printf("[RouteController] ⚠️ Active 线路探测失败 [%s] (连续失败 %d 次): %v", active.ID, failCount, res.Err)
		if failCount == 1 {
			_ = active.TransitionTo(StateDegraded)
		} else if failCount >= c.cfg.FailureThreshold {
			_ = active.TransitionTo(StateFailing)
			_ = active.TransitionTo(StateFailed)
		}
		c.Evaluate()
	} else if active.GetState() == StateDegraded {
		// 恢复健康
		_ = active.TransitionTo(StateActive)
	}
}

// probeStandbys 低频探测 Warm Standby 线路
func (c *RouteController) probeStandbys() {
	c.routesMu.RLock()
	standbys := make([]*Route, len(c.standby))
	copy(standbys, c.standby)
	c.routesMu.RUnlock()

	now := time.Now()
	isPeak := c.peakTracker.IsPeakHour(now, c.cfg.PeakMode, c.cfg.PeakStartHour, c.cfg.PeakEndHour)

	for _, r := range standbys {
		res := c.prober.ProbeRoute(r)
		r.UpdateMetrics(func(m *RouteMetrics) {
			m.HandshakeSuccess = res.Success
			if res.Success {
				m.RTT = res.RTT
				m.FailureCount = 0
				m.SuccessCount++
			} else {
				m.FailureCount++
				m.SuccessCount = 0
			}
			c.scorer.UpdateRouteScores(m, isPeak)
		})
		if !res.Success && r.Metrics.FailureCount >= c.cfg.FailureThreshold {
			_ = r.TransitionTo(StateFailed)
		}
	}
}

// probeFailed 超低频探测 FAILED 线路尝试恢复
func (c *RouteController) probeFailed() {
	c.routesMu.RLock()
	var failed []*Route
	for _, r := range c.routes {
		if r.GetState() == StateFailed || r.GetState() == StateRecovering {
			failed = append(failed, r)
		}
	}
	c.routesMu.RUnlock()

	now := time.Now()
	isPeak := c.peakTracker.IsPeakHour(now, c.cfg.PeakMode, c.cfg.PeakStartHour, c.cfg.PeakEndHour)

	for _, r := range failed {
		res := c.prober.ProbeRoute(r)
		if res.Success {
			r.UpdateMetrics(func(m *RouteMetrics) {
				m.HandshakeSuccess = true
				m.RTT = res.RTT
				m.SuccessCount++
				m.FailureCount = 0
				c.scorer.UpdateRouteScores(m, isPeak)
			})
			if r.GetState() == StateFailed {
				_ = r.TransitionTo(StateRecovering)
			} else if r.GetState() == StateRecovering && r.Metrics.SuccessCount >= c.cfg.RecoveryThreshold {
				_ = r.TransitionTo(StateReady)
				log.Printf("[RouteController] ✅ 线路已恢复可用: [%s] %s", r.ID, r.Name)
			}
		}
	}
}
