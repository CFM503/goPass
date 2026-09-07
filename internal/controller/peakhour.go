package controller

import (
	"sync"
	"time"
)

// HourlyStats 记录单个小时时段的聚合表现
type HourlyStats struct {
	Hour         int     `json:"hour"`          // 0 ~ 23
	SampleCount  int     `json:"sample_count"`  // 样本数
	AvgSpeed     float64 `json:"avg_speed"`     // 平均下载速度 (Bytes/s)
	MinSpeed     float64 `json:"min_speed"`     // 观测到的最低速度 (Bytes/s)
	AvgRTT       float64 `json:"avg_rtt"`       // 平均 RTT (ms)
	AvgLoss      float64 `json:"avg_loss"`      // 平均丢包率 (0.0 ~ 1.0)
	AvgJitter    float64 `json:"avg_jitter"`    // 平均抖动 (ms)
	AvgStability float64 `json:"avg_stability"` // 平均稳定性 (0.0 ~ 1.0)
	FailureRate  float64 `json:"failure_rate"`  // 失败率 (0.0 ~ 1.0)
	failures     int
}

// PeakHourTracker 负责小时级历史数据归集与高峰期研判
type PeakHourTracker struct {
	mu sync.RWMutex
	// routeID -> [24]HourlyStats
	routeHourly map[string]*[24]HourlyStats
}

// NewPeakHourTracker 创建高峰期追踪器
func NewPeakHourTracker() *PeakHourTracker {
	return &PeakHourTracker{
		routeHourly: make(map[string]*[24]HourlyStats),
	}
}

// RecordSample 记录某线路在某小时的性能采样
func (p *PeakHourTracker) RecordSample(routeID string, t time.Time, m *RouteMetrics) {
	p.mu.Lock()
	defer p.mu.Unlock()

	hour := t.Hour()
	stats, ok := p.routeHourly[routeID]
	if !ok {
		var arr [24]HourlyStats
		for i := 0; i < 24; i++ {
			arr[i].Hour = i
		}
		stats = &arr
		p.routeHourly[routeID] = stats
	}

	h := &stats[hour]
	h.SampleCount++
	n := float64(h.SampleCount)

	// 累加平均
	h.AvgSpeed = h.AvgSpeed + (m.DownloadSpeed-h.AvgSpeed)/n
	if h.MinSpeed == 0 || (m.MinSpeed > 0 && m.MinSpeed < h.MinSpeed) {
		h.MinSpeed = m.MinSpeed
	}
	h.AvgRTT = h.AvgRTT + (m.RTT-h.AvgRTT)/n
	h.AvgLoss = h.AvgLoss + (m.PacketLoss-h.AvgLoss)/n
	h.AvgJitter = h.AvgJitter + (m.Jitter-h.AvgJitter)/n
	h.AvgStability = h.AvgStability + (m.Stability-h.AvgStability)/n

	if !m.HandshakeSuccess || m.FailureCount > 0 {
		h.failures++
	}
	h.FailureRate = float64(h.failures) / n
}

// IsPeakHour 判断当前是否属于高峰时段
func (p *PeakHourTracker) IsPeakHour(now time.Time, mode string, startHour, endHour int) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	case "scheduled":
		return isInHourRange(now.Hour(), startHour, endHour)
	case "auto":
		fallthrough
	default:
		// auto 模式：
		// 1. 如果在默认/预设的高峰时间段内（如 18:00 - 23:00），直接视为高峰时段
		if isInHourRange(now.Hour(), startHour, endHour) {
			return true
		}

		// 2. 根据历史数据判定：若当前小时全网线路历史失败率高（>15%）或丢包抬升（>5%）或抖动明显（>30ms），动态进入高峰模式
		p.mu.RLock()
		defer p.mu.RUnlock()

		currentHour := now.Hour()
		totalSamples := 0
		sumLoss := 0.0
		sumJitter := 0.0
		sumFailRate := 0.0
		routeCount := 0

		for _, arr := range p.routeHourly {
			h := arr[currentHour]
			if h.SampleCount >= 5 {
				totalSamples += h.SampleCount
				sumLoss += h.AvgLoss
				sumJitter += h.AvgJitter
				sumFailRate += h.FailureRate
				routeCount++
			}
		}

		if routeCount > 0 {
			avgLoss := sumLoss / float64(routeCount)
			avgJitter := sumJitter / float64(routeCount)
			avgFail := sumFailRate / float64(routeCount)
			if avgFail > 0.15 || avgLoss > 0.05 || avgJitter > 30.0 {
				return true
			}
		}

		return false
	}
}

// GetRouteHourlyStats 获取指定线路的 24 小时统计
func (p *PeakHourTracker) GetRouteHourlyStats(routeID string) [24]HourlyStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if stats, ok := p.routeHourly[routeID]; ok {
		return *stats
	}
	var empty [24]HourlyStats
	for i := 0; i < 24; i++ {
		empty[i].Hour = i
	}
	return empty
}

// GetAllStats 获取所有线路的历史时段数据快照
func (p *PeakHourTracker) GetAllStats() map[string][24]HourlyStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[string][24]HourlyStats, len(p.routeHourly))
	for id, arr := range p.routeHourly {
		result[id] = *arr
	}
	return result
}

// LoadStats 载入持久化的历史数据
func (p *PeakHourTracker) LoadStats(data map[string][24]HourlyStats) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, arr := range data {
		copyArr := arr
		p.routeHourly[id] = &copyArr
	}
}

func isInHourRange(hour, start, end int) bool {
	if start <= end {
		return hour >= start && hour <= end
	}
	// 跨天情况 (如 22点 到 次日 4点)
	return hour >= start || hour <= end
}
