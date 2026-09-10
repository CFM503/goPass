package engine

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CFM503/goPass/internal/version"
	"golang.org/x/net/proxy"
)

type HTTPProxyDialer struct { proxyAddr, username, password string; forward proxy.Dialer }

func NewHTTPProxy(addr, username, password string, forward proxy.Dialer) (proxy.Dialer, error) {
	if !strings.Contains(addr, ":") { addr += ":80" }
	return &HTTPProxyDialer{proxyAddr:addr,username:username,password:password,forward:forward},nil
}

func (d *HTTPProxyDialer) Dial(network, addr string) (net.Conn,error) {
	c,err:=d.forward.Dial("tcp",d.proxyAddr); if err!=nil{return nil,fmt.Errorf("connect HTTP proxy %s: %w",d.proxyAddr,err)}
	fail:=func(e error)(net.Conn,error){_=c.Close();return nil,e}
	_ = c.SetDeadline(time.Now().Add(10*time.Second))

	reqURL,err:=url.Parse("http://"+addr); if err!=nil{return fail(err)}
	reqURL.Scheme=""
	req,err:=http.NewRequest("CONNECT",reqURL.String(),nil); if err!=nil{return fail(err)}
	req.Close=false
	if d.username!="" { auth:=d.username+":"+d.password; req.Header.Set("Proxy-Authorization","Basic "+base64.StdEncoding.EncodeToString([]byte(auth))) }
	req.Header.Set("User-Agent","GoPass/"+strings.TrimPrefix(version.Version,"v"))
	if err=req.Write(c);err!=nil{return fail(fmt.Errorf("send CONNECT request failed: %w",err))}

	br:=bufio.NewReader(c)
	resp,err:=http.ReadResponse(br,req); if err!=nil{return fail(fmt.Errorf("read proxy response failed: %w",err))}
	if resp.StatusCode!=http.StatusOK { io.Copy(io.Discard,resp.Body);resp.Body.Close();return fail(fmt.Errorf("proxy rejected connection: %s",resp.Status)) }
	_ = c.SetDeadline(time.Time{})
	if br.Buffered()>0 { return &BufferedConn{Conn:c,br:br},nil }
	return c,nil
}

type BufferedConn struct { net.Conn; br *bufio.Reader }
func (c *BufferedConn) Read(b []byte)(int,error){ return c.br.Read(b) }
