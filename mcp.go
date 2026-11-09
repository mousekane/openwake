package main

// v1.4 MCP Server：把 v1.3 的 Agent API 包成 MCP 工具，供只认 MCP 的 agent 接管。
// 挂 5055 公网入口的 /mcp，走 Streamable HTTP（无状态模式：每次 POST 直接回单个
// JSON-RPC 响应，不要求 Mcp-Session-Id），认证沿用同一个 Agent API 密钥（Bearer）。
// 实现只依赖标准库：initialize / ping / tools/list / tools/call 四个方法，
// 其余方法回 -32601，通知回 202。协议版本协商：客户端给的版本在支持列表里就原样
// 回，否则回 2025-03-26。
// v1.4.1 兼容旧客户端：POST /mcp 在客户端只接受 SSE 时回 SSE 流（data: JSON）；
// 另提供旧版 SSE 传输：GET /sse 建会话（回 endpoint 事件）+ POST /messages 发请求，
// 结果经 SSE 流回推。两条路共用同一套工具、同一把密钥。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonrpcResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonrpcError `json:"error,omitempty"`
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *jsonrpcError) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jsonrpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr})
}

func rpcError(code int, msg string) *jsonrpcError { return &jsonrpcError{Code: code, Message: msg} }

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func mcpTools() []mcpTool {
	noArgs := map[string]any{"type": "object", "properties": map[string]any{}}
	pcIDArg := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"pc_id": map[string]any{"type": "string", "description": "PC 的 ID，如 pc1（管理页配置里可见）"},
		},
		"required":             []string{"pc_id"},
		"additionalProperties": false,
	}
	auditArg := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit": map[string]any{"type": "integer", "description": "返回条数，默认 20，最多 100"},
		},
	}
	return []mcpTool{
		{Name: "openwake_health", Description: "查 OpenWake 健康状态，返回版本号", InputSchema: noArgs},
		{Name: "openwake_status", Description: "查全部 Win PC 开关机状态和 OpenWrt 在线状态（不返回 IP/MAC/主机地址）", InputSchema: noArgs},
		{Name: "openwake_audit", Description: "查最近的 Agent 操作审计记录", InputSchema: auditArg},
		{Name: "openwake_pc_wake", Description: "发送 Wake-on-LAN 魔术包，开机指定 PC", InputSchema: pcIDArg},
		{Name: "openwake_pc_shutdown", Description: "SSH 关机指定 Win PC", InputSchema: pcIDArg},
		{Name: "openwake_pc_restart", Description: "SSH 重启指定 Win PC", InputSchema: pcIDArg},
		{Name: "openwake_openwrt_poweroff", Description: "SSH 关机 OpenWrt 宿主机。注意：关机后本服务随之下线，需手动按电源键恢复", InputSchema: noArgs},
		{Name: "openwake_ddns_refresh", Description: "立即刷新一次 Cloudflare DDNS", InputSchema: noArgs},
	}
}

// agentStatusData 与 /api/v1/agent/status 同一份快照，供 REST 与 MCP 共用。
func agentStatusData() map[string]any {
	statusMu.RLock()
	pcs := pcStatuses
	owOn := owOnline
	statusMu.RUnlock()
	if pcs == nil {
		pcs = []pcStatus{}
	}
	out := make([]map[string]any, 0, len(pcs))
	for _, p := range pcs {
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "online": p.Online})
	}
	return map[string]any{
		"ok": true, "version": appVersion, "domain": getConfig().DDNS.Domain,
		"pcs": out, "openwrt": map[string]any{"online": owOn},
	}
}

// mcpCooldown：MCP 写操作 5 秒冷却（与 REST 共用同一张表），返回是否放行。
func mcpCooldown(key string) bool {
	publicActionMu.Lock()
	defer publicActionMu.Unlock()
	if last, ok := publicActionLast[key]; ok && time.Since(last) < 5*time.Second {
		return false
	}
	publicActionLast[key] = time.Now()
	return true
}

func mcpToolResult(text string, isErr bool) map[string]any {
	r := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
	if isErr {
		r["isError"] = true
	}
	return r
}

func mcpMustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func mcpCallTool(name string, args map[string]any) (map[string]any, *jsonrpcError) {
	switch name {
	case "openwake_health":
		return mcpToolResult(mcpMustJSON(map[string]any{"ok": true, "version": appVersion, "time": time.Now().Format(time.RFC3339)}), false), nil
	case "openwake_status":
		return mcpToolResult(mcpMustJSON(agentStatusData()), false), nil
	case "openwake_audit":
		limit := 20
		if v, ok := args["limit"].(float64); ok && v > 0 {
			limit = int(v)
		}
		if limit > 100 {
			limit = 100
		}
		entries := getAgentAudit()
		if len(entries) > limit {
			entries = entries[:limit]
		}
		return mcpToolResult(mcpMustJSON(map[string]any{"ok": true, "entries": entries}), false), nil
	case "openwake_pc_wake", "openwake_pc_shutdown", "openwake_pc_restart":
		pcID, _ := args["pc_id"].(string)
		if strings.TrimSpace(pcID) == "" {
			return nil, rpcError(-32602, "缺少必填参数 pc_id")
		}
		action := strings.TrimPrefix(name, "openwake_pc_")
		if !mcpCooldown("mcp:pc:" + pcID + ":" + action) {
			return mcpToolResult("操作太频繁，请稍后再试", true), nil
		}
		pc := findPC(getConfig(), pcID)
		if pc == nil {
			return mcpToolResult("找不到该 PC："+pcID, true), nil
		}
		var err error
		var msg string
		switch action {
		case "wake":
			err = sendWOL(*pc)
			msg = "魔术包已发送，等待 PC 启动（约 10-60 秒）"
		case "shutdown":
			err = windowsShutdown(*pc)
			msg = "关机命令已发送"
		case "restart":
			err = windowsRestart(*pc)
			msg = "重启命令已发送"
		}
		if err != nil {
			logAgent("mcp.pc."+action, pcID, "fail", err.Error())
			return mcpToolResult("执行失败："+err.Error(), true), nil
		}
		logAgent("mcp.pc."+action, pcID, "ok", msg)
		go func() { time.Sleep(3 * time.Second); refreshStatuses() }()
		return mcpToolResult(msg, false), nil
	case "openwake_openwrt_poweroff":
		if !mcpCooldown("mcp:openwrt:poweroff") {
			return mcpToolResult("操作太频繁，请稍后再试", true), nil
		}
		if err := openWrtPoweroff(getConfig()); err != nil {
			logAgent("mcp.openwrt.poweroff", "openwrt", "fail", err.Error())
			return mcpToolResult("执行失败："+err.Error(), true), nil
		}
		logAgent("mcp.openwrt.poweroff", "openwrt", "ok", "OpenWrt 关机命令已发送")
		return mcpToolResult("OpenWrt 关机命令已发送", false), nil
	case "openwake_ddns_refresh":
		if !mcpCooldown("mcp:ddns:refresh") {
			return mcpToolResult("操作太频繁，请稍后再试", true), nil
		}
		go runDDNSOnce()
		logAgent("mcp.ddns.refresh", "ddns", "ok", "DDNS 刷新已触发")
		return mcpToolResult("DDNS 刷新中，稍后查看结果", false), nil
	default:
		return nil, rpcError(-32602, "未知工具："+name)
	}
}

var mcpSupportedVersions = map[string]bool{
	"2025-03-26": true, "2025-06-18": true,
	"2024-11-05": true, "2024-10-07": true,
}

// dispatchRPC：解析并执行一条 JSON-RPC 请求，返回响应体（通知返回 nil，不回包）。
func dispatchRPC(body []byte) []byte {
	marshal := func(resp jsonrpcResponse) []byte {
		b, _ := json.Marshal(resp)
		return b
	}
	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Method == "" {
		return marshal(jsonrpcResponse{JSONRPC: "2.0", Error: rpcError(-32700, "请求体解析失败")})
	}
	// 通知（无 id、无需回包）
	if strings.HasPrefix(req.Method, "notifications/") || req.ID == nil {
		return nil
	}
	resp := func(result any, rpcErr *jsonrpcError) []byte {
		return marshal(jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr})
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		ver := "2025-03-26"
		if mcpSupportedVersions[p.ProtocolVersion] {
			ver = p.ProtocolVersion
		}
		return resp(map[string]any{
			"protocolVersion": ver,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "openwake", "version": appVersion},
		}, nil)
	case "ping":
		return resp(map[string]any{}, nil)
	case "tools/list":
		return resp(map[string]any{"tools": mcpTools()}, nil)
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return resp(nil, rpcError(-32602, "tools/call 参数无效"))
		}
		if p.Arguments == nil {
			p.Arguments = map[string]any{}
		}
		result, rpcErr := mcpCallTool(p.Name, p.Arguments)
		return resp(result, rpcErr)
	default:
		return resp(nil, rpcError(-32601, "不支持的方法："+req.Method))
	}
}

// mcpHandler：Streamable HTTP。客户端只接受 SSE 时回 SSE 流，否则回 JSON。
func mcpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		writeJSON(w, 405, map[string]any{"ok": false, "error": "MCP 只接受 POST"})
		return
	}
	if !agentAuth(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeRPC(w, nil, nil, rpcError(-32700, "请求体解析失败"))
		return
	}
	resp := dispatchRPC(body)
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte("data: " + string(resp) + "\n\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

// ---- 旧版 SSE 传输（v1.4.1）：GET /sse 建会话 + POST /messages 发请求 ----

type sseSession struct {
	ch chan []byte
}

var (
	sseMu       sync.Mutex
	sseSessions = map[string]*sseSession{}
)

func sseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		writeJSON(w, 405, map[string]any{"ok": false, "error": "SSE 建会话只接受 GET"})
		return
	}
	if !agentAuth(w, r) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]any{"ok": false, "error": "服务器不支持 SSE 流"})
		return
	}
	id := newSessionToken()
	sess := &sseSession{ch: make(chan []byte, 16)}
	sseMu.Lock()
	sseSessions[id] = sess
	sseMu.Unlock()
	defer func() {
		sseMu.Lock()
		delete(sseSessions, id)
		sseMu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /messages?session_id=%s\n\n", id)
	flusher.Flush()
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg, ok := <-sess.ch:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ticker.C:
			_, _ = w.Write([]byte(": keep-alive\n\n"))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func messagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		writeJSON(w, 405, map[string]any{"ok": false, "error": "SSE 消息只接受 POST"})
		return
	}
	if !agentAuth(w, r) {
		return
	}
	sid := r.URL.Query().Get("session_id")
	sseMu.Lock()
	sess, ok := sseSessions[sid]
	sseMu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"ok": false, "error": "会话不存在或已断开，请重新 GET /sse 建会话"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	resp := dispatchRPC(body)
	if resp != nil {
		select {
		case sess.ch <- resp:
		case <-time.After(5 * time.Second):
		}
	}
	w.WriteHeader(http.StatusAccepted)
}
