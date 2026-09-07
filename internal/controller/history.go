package controller

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// HistoryRecord 持久化数据模型
type HistoryRecord struct {
	UpdatedAt   time.Time                    `json:"updated_at"`
	Routes      []RouteSnapshotRecord        `json:"routes"`
	HourlyStats map[string][24]HourlyStats   `json:"hourly_stats"`
}

type RouteSnapshotRecord struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Address  string       `json:"address"`
	Port     int          `json:"port"`
	Protocol string       `json:"protocol"`
	State    RouteState   `json:"state"`
	Metrics  RouteMetrics `json:"metrics"`
}

// HistoryStorage 异步周期持久化管理器
type HistoryStorage struct {
	filePath string
	mu       sync.Mutex
}

// NewHistoryStorage 创建持久化管理器 (若 filePath 为空或 'none' 则不进行磁盘读写)
func NewHistoryStorage(filePath string) *HistoryStorage {
	return &HistoryStorage{filePath: filePath}
}

// SaveAsync 异步批量保存（绝不阻塞主调度与转发）
func (h *HistoryStorage) SaveAsync(routes []*Route, hourly map[string][24]HourlyStats) {
	if h.filePath == "" || h.filePath == "none" || h.filePath == ":memory:" {
		return
	}

	// 先在调用方锁外完成浅拷贝以减少锁定开销
	var records []RouteSnapshotRecord
	for _, r := range routes {
		snap := r.Snapshot()
		records = append(records, RouteSnapshotRecord{
			ID:       snap.ID,
			Name:     snap.Name,
			Address:  snap.Address,
			Port:     snap.Port,
			Protocol: snap.Protocol,
			State:    snap.State,
			Metrics:  snap.Metrics,
		})
	}

	go func() {
		h.mu.Lock()
		defer h.mu.Unlock()

		data := HistoryRecord{
			UpdatedAt:   time.Now(),
			Routes:      records,
			HourlyStats: hourly,
		}

		raw, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Printf("[RouteController] 历史数据序列化失败: %v", err)
			return
		}

		tmpFile := h.filePath + ".tmp"
		if err := os.WriteFile(tmpFile, raw, 0644); err != nil {
			log.Printf("[RouteController] 历史数据写入临时文件失败: %v", err)
			return
		}

		// Windows 下若目标存在需要先移除以保证原子替换成功
		_ = os.Remove(h.filePath)
		if err := os.Rename(tmpFile, h.filePath); err != nil {
			log.Printf("[RouteController] 历史数据原子更新失败: %v", err)
		}
	}()
}

// Load 读取持久化数据
func (h *HistoryStorage) Load() (*HistoryRecord, error) {
	if h.filePath == "" || h.filePath == "none" || h.filePath == ":memory:" {
		return nil, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	raw, err := os.ReadFile(h.filePath)
	if err != nil {
		return nil, err
	}

	var rec HistoryRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}
