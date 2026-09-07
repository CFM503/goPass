package controller

import (
	"math"
)

// ScoreWeights 定义评分权重
type ScoreWeights struct {
	Speed      float64
	Stability  float64
	PacketLoss float64
	Jitter     float64
	Latency    float64
	Handshake  float64
}

// DefaultNormalWeights 正常时段权重
var DefaultNormalWeights = ScoreWeights{
	Speed:      0.30,
	Stability:  0.25,
	PacketLoss: 0.15,
	Jitter:     0.15,
	Latency:    0.10,
	Handshake:  0.05,
}

// DefaultPeakWeights 高峰时段权重 (更侧重稳定与低丢包)
var DefaultPeakWeights = ScoreWeights{
	Stability:  0.30,
	Speed:      0.30,
	PacketLoss: 0.20,
	Jitter:     0.15,
	Latency:    0.05,
	Handshake:  0.00,
}

// HistoryWeights 历史平滑权重
type HistoryWeights struct {
	Instant   float64 // 瞬时权重 (默认 0.40)
	ShortTerm float64 // 近期平滑权重 (默认 0.40)
	LongTerm  float64 // 长期平滑权重 (默认 0.20)
}

// DefaultHistoryWeights 默认历史平滑权重
var DefaultHistoryWeights = HistoryWeights{
	Instant:   0.40,
	ShortTerm: 0.40,
	LongTerm:  0.20,
}

// Scorer 线路评分计算器
type Scorer struct {
	NormalWeights  ScoreWeights
	PeakWeights    ScoreWeights
	HistoryWeights HistoryWeights

	// EWMA 平滑系数
	AlphaShort float64 // 短期衰减系数 (~5-15分钟)
	AlphaLong  float64 // 长期衰减系数 (~数小时)
}

// NewScorer 创建评分器
func NewScorer() *Scorer {
	return &Scorer{
		NormalWeights:  DefaultNormalWeights,
		PeakWeights:    DefaultPeakWeights,
		HistoryWeights: DefaultHistoryWeights,
		AlphaShort:     0.25,
		AlphaLong:      0.08,
	}
}

// CalcInstantScore 计算单次测量瞬时评分 (0 ~ 100)
func (s *Scorer) CalcInstantScore(m *RouteMetrics, isPeak bool) float64 {
	// 明确失败条件：明确握手失败、100%丢包、或既无握手成功也无健康探测可用
	if (m.HandshakeKnown && !m.HandshakeSuccess) || m.PacketLoss >= 1.0 {
		return 0.0
	}
	if !m.HandshakeSuccess && !m.ProbeSuccess {
		return 0.0
	}

	w := s.NormalWeights
	if isPeak {
		w = s.PeakWeights
	}

	// 1. 速度分 (0 ~ 100)：融合下载速度、单线程速度与最低速度，采用对数饱和曲线
	effSpeed := m.DownloadSpeed
	if m.SingleSpeed > 0 && m.SingleSpeed > effSpeed {
		effSpeed = m.SingleSpeed
	}
	if m.MinSpeed > 0 && m.MinSpeed < effSpeed {
		effSpeed = effSpeed*0.7 + m.MinSpeed*0.3
	}
	speedMB := effSpeed / (1024 * 1024)
	speedScore := 0.0
	if speedMB > 0 {
		// 1MB/s -> ~27分, 5MB/s -> ~56分, 20MB/s -> ~85分, 50MB/s+ -> 100分
		speedScore = math.Min(100.0, 15.0*math.Log2(1.0+speedMB*2.5))
	}

	// 2. 稳定性分 (0 ~ 100)
	stab := m.Stability
	if stab <= 0 {
		stab = 0.5 // 未测出时中立值
	}
	if stab > 1.0 {
		stab = 1.0
	}
	stabilityScore := stab * 100.0

	// 3. 丢包分 (0 ~ 100)：0% 丢包 = 100分，10% 丢包 = 0分（快速扣分保障质量）
	loss := m.PacketLoss
	if loss < 0 {
		loss = 0
	}
	lossScore := math.Max(0.0, (1.0-loss*10.0)*100.0)

	// 4. Jitter 抖动分 (0 ~ 100)：0ms = 100分, >=50ms = 0分
	jitterScore := math.Max(0.0, 100.0-m.Jitter*2.0)

	// 5. Latency 延迟分 (0 ~ 100)：<=30ms 满分，>=400ms 为 0
	latencyScore := 100.0
	if m.RTT > 30.0 {
		latencyScore = math.Max(0.0, 100.0-(m.RTT-30.0)*0.27)
	}

	// 6. 握手分
	handshakeScore := 100.0
	if m.HandshakeKnown && !m.HandshakeSuccess {
		handshakeScore = 0.0
	} else if !m.HandshakeKnown {
		handshakeScore = 50.0 // 未测试握手时中立，不制造虚假满分
	}

	total := speedScore*w.Speed +
		stabilityScore*w.Stability +
		lossScore*w.PacketLoss +
		jitterScore*w.Jitter +
		latencyScore*w.Latency +
		handshakeScore*w.Handshake

	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}
	return total
}

// UpdateRouteScores 更新线路的 Instant、ShortTerm、LongTerm 与 Final Score
func (s *Scorer) UpdateRouteScores(m *RouteMetrics, isPeak bool) {
	instant := s.CalcInstantScore(m, isPeak)
	m.InstantScore = instant

	if m.ShortTermScore == 0 && m.LongTermScore == 0 {
		// 冷启动初始化
		m.ShortTermScore = instant
		m.LongTermScore = instant
	} else {
		// EWMA 平滑
		m.ShortTermScore = (1-s.AlphaShort)*m.ShortTermScore + s.AlphaShort*instant
		m.LongTermScore = (1-s.AlphaLong)*m.LongTermScore + s.AlphaLong*instant
	}

	// 计算综合终分 FinalScore
	hw := s.HistoryWeights
	final := instant*hw.Instant + m.ShortTermScore*hw.ShortTerm + m.LongTermScore*hw.LongTerm
	if final < 0 {
		final = 0
	}
	if final > 100 {
		final = 100
	}
	m.Score = final
	m.FinalScore = final
}
