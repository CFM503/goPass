package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yourusername/gopass/internal/engine"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var clientSlicePool = sync.Pool{
	New: func() interface{} {
		s := make([]*websocket.Conn, 0, 16)
		return &s
	},
}

// WSMessage 预定义结构，替代 map[string]interface{} 减少 JSON 编码分配
type WSMessage struct {
	PID         int              `json:"pid"`
	Connections int32            `json:"connections"`
	RX          string           `json:"rx"`
	TX          string           `json:"tx"`
	Active      []engine.ConnInfo `json:"active"`
}

type WSServer struct {
	clients map[*websocket.Conn]struct{}
	mu      sync.RWMutex
	eng     *engine.Engine

	interval       atomic.Int64
	cachedInterval atomic.Int64
}

func NewWSServer(eng *engine.Engine) *WSServer {
	ws := &WSServer{
		clients: make(map[*websocket.Conn]struct{}),
		eng:     eng,
	}
	ws.interval.Store(5)
	go ws.broadcastLoop()
	return ws
}

func (ws *WSServer) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS Upgrade error: %v", err)
		return
	}

	ws.mu.Lock()
	ws.clients[conn] = struct{}{}
	ws.mu.Unlock()

	defer func() {
		ws.mu.Lock()
		delete(ws.clients, conn)
		ws.mu.Unlock()
		conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (ws *WSServer) broadcastLoop() {
	ticker := time.NewTicker(time.Duration(ws.interval.Load()) * time.Second)
	defer ticker.Stop()

	var lastRx, lastTx int64
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	for range ticker.C {
		interval := ws.interval.Load()

		if ws.eng != nil {
			cached := ws.cachedInterval.Load()
			if cached == 0 || cached != interval {
				if cfg := ws.eng.GetConfig(); cfg != nil {
					newInterval := int64(cfg.API.WSRefreshInterval)
					if newInterval >= 1 && newInterval != interval {
						ws.interval.Store(newInterval)
						interval = newInterval
						ticker.Reset(time.Duration(interval) * time.Second)
					}
					ws.cachedInterval.Store(interval)
				}
			}
		}

		pid := os.Getpid()
		var conns int32
		var currRx, currTx int64
		var active []engine.ConnInfo

		if ws.eng != nil && ws.eng.Stats != nil {
			pid = ws.eng.Stats.PID
			conns = ws.eng.Stats.Connections
			currRx = ws.eng.Stats.RxBytes
			currTx = ws.eng.Stats.TxBytes
			active = ws.eng.Stats.GetActive()
		}

		if active == nil {
			active = []engine.ConnInfo{}
		}

		rxPerSec := (currRx - lastRx) / interval
		txPerSec := (currTx - lastTx) / interval
		lastRx = currRx
		lastTx = currTx

		msg := WSMessage{
			PID:         pid,
			Connections: conns,
			RX:          formatBytes(rxPerSec) + "/s",
			TX:          formatBytes(txPerSec) + "/s",
			Active:      active,
		}

		buf.Reset()
		if err := enc.Encode(msg); err != nil {
			continue
		}
		data := buf.Bytes()

		clientsPtr := clientSlicePool.Get().(*[]*websocket.Conn)
		*clientsPtr = (*clientsPtr)[:0]
		ws.mu.RLock()
		for conn := range ws.clients {
			*clientsPtr = append(*clientsPtr, conn)
		}
		ws.mu.RUnlock()

		for _, conn := range *clientsPtr {
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				conn.Close()
				ws.mu.Lock()
				delete(ws.clients, conn)
				ws.mu.Unlock()
			}
		}
		clientSlicePool.Put(clientsPtr)
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return itoa64(b) + " B"
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return formatFloat(float64(b)/float64(div)) + " " + "KMGTPE"[exp:exp+1] + "B"
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func formatFloat(f float64) string {
	v := int64(f*10 + 0.5)
	intPart := v / 10
	fracPart := v % 10
	return itoa64(intPart) + "." + itoa64(fracPart)
}
