package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/CFM503/goPass/internal/engine"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type WSServer struct { clients map[*websocket.Conn]bool; mu sync.Mutex; eng *engine.Engine }

func NewWSServer(eng *engine.Engine) *WSServer { ws:=&WSServer{clients:make(map[*websocket.Conn]bool),eng:eng}; go ws.broadcastLoop(); return ws }

func (ws *WSServer) HandleWS(w http.ResponseWriter,r *http.Request){
	conn,err:=upgrader.Upgrade(w,r,nil); if err!=nil{log.Printf("WS Upgrade error: %v",err);return}
	ws.mu.Lock();ws.clients[conn]=true;ws.mu.Unlock()
	defer func(){ws.mu.Lock();delete(ws.clients,conn);ws.mu.Unlock();_=conn.Close()}()
	for{if _,_,err=conn.ReadMessage();err!=nil{return}}
}

func (ws *WSServer) broadcastLoop(){
	interval:=5
	if ws.eng!=nil&&ws.eng.GetConfig()!=nil&&ws.eng.GetConfig().API.WSRefreshInterval>=1{interval=ws.eng.GetConfig().API.WSRefreshInterval}
	ticker:=time.NewTicker(time.Duration(interval)*time.Second);defer ticker.Stop()
	var lastRx,lastTx int64
	for range ticker.C{
		newInterval:=5
		if ws.eng!=nil&&ws.eng.GetConfig()!=nil&&ws.eng.GetConfig().API.WSRefreshInterval>=1{newInterval=ws.eng.GetConfig().API.WSRefreshInterval}
		if newInterval!=interval{interval=newInterval;ticker.Reset(time.Duration(interval)*time.Second)}

		pid:=os.Getpid(); conns:=0; var currRx,currTx int64; var active []map[string]interface{}
		if ws.eng!=nil&&ws.eng.Stats!=nil{
			pid=ws.eng.Stats.PID
			active=ws.eng.Stats.GetActive()
			conns=len(active)
			currRx=atomic.LoadInt64(&ws.eng.Stats.RxBytes)
			currTx=atomic.LoadInt64(&ws.eng.Stats.TxBytes)
		}
		rxPerSec:=(currRx-lastRx)/int64(interval); txPerSec:=(currTx-lastTx)/int64(interval); lastRx,lastTx=currRx,currTx
		if active==nil{active=[]map[string]interface{}{}}
		data,_:=json.Marshal(map[string]interface{}{"pid":pid,"connections":conns,"rx":formatBytes(rxPerSec)+"/s","tx":formatBytes(txPerSec)+"/s","active":active})

		ws.mu.Lock()
		for conn:=range ws.clients{
			_ = conn.SetWriteDeadline(time.Now().Add(5*time.Second))
			if err:=conn.WriteMessage(websocket.TextMessage,data);err!=nil{_ = conn.Close();delete(ws.clients,conn)}
		}
		ws.mu.Unlock()
	}
}

func formatBytes(b int64) string { const unit=int64(1024); if b<unit{return fmt.Sprintf("%d B",b)}; div,exp:=unit,0; for n:=b/unit;n>=unit;n/=unit{div*=unit;exp++}; return fmt.Sprintf("%.1f %cB",float64(b)/float64(div),"KMGTPE"[exp]) }
