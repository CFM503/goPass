package controller

import (
	"fmt"
	"sync"
	"time"
)

// RouteState 代表线路生命周期状态
type RouteState string

const (
	StateUnknown    RouteState = "UNKNOWN"
	StateTesting    RouteState = "TESTING"
	StateReady      RouteState = "READY"
	StateActive     RouteState = "ACTIVE"
	StateDegraded   RouteState = "DEGRADED"
	StateFailing    RouteState = "FAILING"
	StateFailed     RouteState = "FAILED"
	StateRecovering RouteState = "RECOVERING"
	StateStandby    RouteState = "STANDBY"
)

// RouteMetrics 记录线路实时与历史性能指标
type RouteMetrics struct {
	RTT              float64       `json:"rtt"`               // 往返延迟 (ms)
	PacketLoss       float64       `json:"packet_loss"`       // 丢包率 (0.0 ~ 1.0)
	Jitter           float64       `json:"jitter"`            // 抖动 (ms)
	DownloadSpeed    float64       `json:"download_speed"`    // 下载速度 (Bytes/s)
	SingleSpeed      float64       `json:"single_speed"`      // 单线程测速 (Bytes/s)
	MinSpeed         float64       `json:"min_speed"`         // 最低瞬时速度 (Bytes/s)
	Stability        float64       `json:"stability"`         // 稳定性指数 (0.0 ~ 1.0)
	LoadLatency      float64       `json:"load_latency"`      // 负载延迟 (ms)
	HandshakeSuccess bool          `json:"handshake_success"` // 握手成功状态
	HandshakeKnown   bool          `json:"handshake_known"`   // 是否包含明确握手检测
	ProbeSuccess     bool          `json:"probe_success"`     // 本次探测/上报是否判定为健康可用
	FailureCount     int           `json:"failure_count"`     // 连续失败次数
	SuccessCount     int           `json:"success_count"`     // 连续成功次数
	StableDuration   time.Duration `json:"stable_duration"`   // 持续处于稳定高分状态的时长
	LastUpdate       time.Time     `json:"last_update"`       // 指标最后更新时间
	LastSwitch       time.Time     `json:"last_switch"`       // 线路最后被切换激活时间
	Score            float64       `json:"score"`             // 当前综合评分 (0 ~ 100)
	FinalScore       float64       `json:"final_score"`       // 最终综合评分 (等同 Score)
	InstantScore     float64       `json:"instant_score"`     // 瞬时测量评分
	ShortTermScore   float64       `json:"short_term_score"`  // 近期平滑评分 (5~15分钟)
	LongTermScore    float64       `json:"long_term_score"`   // 长期平滑评分 (数小时)
}

// Route 线路实体
type Route struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Address  string     `json:"address"`
	Port     int        `json:"port"`
	Protocol string     `json:"protocol"` // "socks5" | "http"
	Type     string     `json:"type"`     // "goway" | "external"
	State    RouteState `json:"state"`
	Metrics  RouteMetrics `json:"metrics"`

	// 状态计时与内部辅助
	stateEnteredAt   time.Time
	degradedSince    time.Time     // 连续劣变起始时间（使用真实时间防误切）

	mu sync.RWMutex
}

// NewRoute 创建一条新线路
func NewRoute(id, name, address string, port int, protocol, rType string) *Route {
	if protocol == "" {
		protocol = "socks5"
	}
	if rType == "" {
		rType = "goway"
	}
	now := time.Now()
	return &Route{
		ID:             id,
		Name:           name,
		Address:        address,
		Port:           port,
		Protocol:       protocol,
		Type:           rType,
		State:          StateUnknown,
		stateEnteredAt: now,
		Metrics: RouteMetrics{
			HandshakeSuccess: true,
			HandshakeKnown:   false,
			ProbeSuccess:     true,
			Stability:        1.0,
			LastUpdate:       now,
		},
	}
}

// Snapshot 获取线路的线程安全只读快照
func (r *Route) Snapshot() Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Route{
		ID:             r.ID,
		Name:           r.Name,
		Address:        r.Address,
		Port:           r.Port,
		Protocol:       r.Protocol,
		Type:           r.Type,
		State:          r.State,
		Metrics:        r.Metrics,
		stateEnteredAt: r.stateEnteredAt,
	}
}

// CanTransitionTo 检查状态机跃迁合法性
// 严禁: ACTIVE -> ACTIVE, ACTIVE -> FAILED(禁止直接跳崖，必须 ACTIVE -> DEGRADED -> FAILING -> FAILED)
func CanTransitionTo(current, next RouteState) bool {
	if current == next {
		return false
	}
	switch current {
	case StateUnknown:
		return next == StateTesting || next == StateReady || next == StateFailed
	case StateTesting:
		return next == StateReady || next == StateFailed
	case StateReady:
		return next == StateActive || next == StateStandby || next == StateTesting || next == StateDegraded || next == StateFailed
	case StateStandby:
		return next == StateActive || next == StateDegraded || next == StateFailing || next == StateFailed || next == StateReady
	case StateActive:
		// 严禁直接跳到 FAILED 或 ACTIVE！只能先进入 DEGRADED，或被优雅替换为 STANDBY
		return next == StateDegraded || next == StateStandby
	case StateDegraded:
		return next == StateFailing || next == StateActive || next == StateStandby || next == StateFailed
	case StateFailing:
		return next == StateFailed || next == StateDegraded || next == StateStandby || next == StateActive
	case StateFailed:
		return next == StateRecovering
	case StateRecovering:
		return next == StateReady || next == StateFailed
	default:
		return false
	}
}

// TransitionTo 执行状态跃迁并更新内部计时
func (r *Route) TransitionTo(next RouteState) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !CanTransitionTo(r.State, next) {
		return fmt.Errorf("非法状态跃迁: %s -> %s", r.State, next)
	}

	r.State = next
	r.stateEnteredAt = time.Now()
	if next == StateActive {
		r.Metrics.LastSwitch = r.stateEnteredAt
	}
	return nil
}

// GetState 获取当前状态
func (r *Route) GetState() RouteState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.State
}

// GetScore 获取当前最新综合评分
func (r *Route) GetScore() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Metrics.Score
}

// GetMetrics 获取当前最新指标副本
func (r *Route) GetMetrics() RouteMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Metrics
}

// GetDegradedSince 获取退化起始时间
func (r *Route) GetDegradedSince() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.degradedSince
}

// SetDegradedSince 设置退化起始时间
func (r *Route) SetDegradedSince(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.degradedSince = t
}

// UpdateMetrics 更新指标并返回更新后的指标副本（保证调用方无需二次裸读）
func (r *Route) UpdateMetrics(updater func(m *RouteMetrics)) RouteMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()

	updater(&r.Metrics)
	r.Metrics.LastUpdate = time.Now()
	return r.Metrics
}
