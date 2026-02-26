package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yourusername/gopass/internal/engine"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow local UI
	},
}

type WSServer struct {
	clients map[*websocket.Conn]bool
	mu      sync.Mutex
	eng     *engine.Engine
}

func NewWSServer(eng *engine.Engine) *WSServer {
	ws := &WSServer{
		clients: make(map[*websocket.Conn]bool),
		eng:     eng,
	}
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
	ws.clients[conn] = true
	ws.mu.Unlock()

	defer func() {
		ws.mu.Lock()
		delete(ws.clients, conn)
		ws.mu.Unlock()
		conn.Close()
	}()

	// Keep alive loop
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (ws *WSServer) broadcastLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastRx, lastTx int64

	for range ticker.C {
		pid := os.Getpid()
		var conns int
		var currRx, currTx int64
		var active []map[string]interface{}

		if ws.eng != nil && ws.eng.Stats != nil {
			pid = ws.eng.Stats.PID
			conns = ws.eng.Stats.Connections
			currRx = ws.eng.Stats.RxBytes
			currTx = ws.eng.Stats.TxBytes
			active = ws.eng.Stats.Active
		}

		rxPerSec := currRx - lastRx
		txPerSec := currTx - lastTx
		lastRx = currRx
		lastTx = currTx

		if active == nil {
			active = []map[string]interface{}{}
		}

		msg := map[string]interface{}{
			"pid":         pid,
			"connections": conns,
			"rx":          formatBytes(rxPerSec) + "/s",
			"tx":          formatBytes(txPerSec) + "/s",
			"active":      active,
		}

		data, _ := json.Marshal(msg)

		ws.mu.Lock()
		for conn := range ws.clients {
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				conn.Close()
				delete(ws.clients, conn)
			}
		}
		ws.mu.Unlock()
	}
}

// formatBytes helper for pretty printing bytes
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
