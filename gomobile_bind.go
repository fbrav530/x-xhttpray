package tunnel

// gomobile.go —— gomobile 绑定层
//
// 把桌面版的 package main 改造成 Android 可用的库：
//   - 原 main() 里「解析命令行 → 起监听 → 起连接池」的流程，
//     在这里重写为 StartSocksProxy(参数...) 供 Java 调用。
//   - Java 侧（TProxyService.java）需要三个入口：
//       Tunnel.startSocksProxy(...)
//       Tunnel.waitSocksProxyReady(ms)
//       Tunnel.stopSocksProxy()
//     签名与原 Android 版保持一致，Java 代码无需改动。

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	serviceMu sync.Mutex

	// 本地 SOCKS5 监听器（可关闭）
	socks5Ln net.Listener

	// 由 StartSocksProxy 建立并持有，StopSocksProxy 时清理
	activePool *ECHPool
	activeCtx  context.Context
	activeStop context.CancelFunc
	running    bool
)

// StartSocksProxy 启动 SOCKS5 代理并连接 xhttp 服务端。
//
// 参数与 Java 调用顺序一致：
//
//	host           本地监听地址，如 "127.0.0.1:1080"
//	wsServer       服务端地址，必须 wss://host:port/path
//	n              每个 IP 建立的通道数
//	udpBlockPortsStr  UDP 拦截端口，如 "443,8443"
//	dns            ECH 公钥查询用的 DNS
//	ech            ECH 域名
//	ip             将服务端主机名固定到指定 IP，可为空
//	tkn            token（xhttp 走 X-Token 头）
//	fb             true=禁用 ECH，回落普通 TLS 1.3
//	ipsPref        "4" / "6" / "4,6" / "6,4"
//	insecureFlag   true=跳过证书校验
func StartSocksProxy(host, wsServer string, n int, udpBlockPortsStr, dns, ech, ip, tkn string, fb bool, ipsPref string, insecureFlag bool) error {
	if wsServer == "" {
		return fmt.Errorf("缺少服务地址")
	}
	if host == "" {
		return fmt.Errorf("缺少本地监听地址")
	}

	serviceMu.Lock()
	defer serviceMu.Unlock()

	if running {
		return fmt.Errorf("服务已启动")
	}

	// ---- 参数落地到桌面版的全局变量 ----
	// listenAddr / ipAddr 在桌面版只服务于命令行分支判断，
	// 这里由参数直接驱动，不再赋值以免留下无意义状态。
	forwardAddr = wsServer
	token = tkn
	fallback = fb
	insecure = insecureFlag
	enableHtml = false

	if dns != "" {
		dnsServer = dns
	}
	if ech != "" {
		echDomain = ech
	}
	if n <= 0 {
		n = 1
	}
	connectionNum = n
	ipStrategy = parseIPStrategy(ipsPref)

	// ---- 解析服务端地址 ----
	scheme := ""
	lower := strings.ToLower(wsServer)
	if strings.HasPrefix(lower, "wss://") {
		scheme = "wss"
	} else if strings.HasPrefix(lower, "ws://") {
		scheme = "ws"
	} else {
		return fmt.Errorf("仅支持 ws:// 或 wss:// (当前: %s)", wsServer)
	}
	// 补尾斜杠，避免路径为空导致握手 404
	if idx := strings.Index(wsServer, "://"); idx >= 0 {
		rest := wsServer[idx+3:]
		if !strings.Contains(rest, "/") {
			wsServer += "/"
			forwardAddr = wsServer
		}
	}

	// ---- 目标 IP 列表 ----
	var targetIPs []string
	if ip != "" {
		for _, p := range strings.Split(ip, ",") {
			if t := strings.TrimSpace(p); t != "" {
				targetIPs = append(targetIPs, t)
			}
		}
	}

	// ---- UDP 拦截端口 ----
	if udpBlockPortsStr != "" {
		udpBlockPorts = make(map[int]struct{})
		for _, p := range strings.Split(udpBlockPortsStr, ",") {
			var port int
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &port); err == nil {
				if port > 0 && port < 65536 {
					udpBlockPorts[port] = struct{}{}
				}
			}
		}
	}

	// ---- wss 需要 ECH ----
	if scheme == "wss" {
		if insecure && !fallback {
			fallback = true
		}
		if !fallback {
			if err := prepareECH(); err != nil {
				return fmt.Errorf("获取 ECH 公钥失败: %w", err)
			}
		}
	}

	// ---- 先起本地 SOCKS5 监听，保证 waitSocksProxyReady 能尽快返回 ----
	ln, err := net.Listen("tcp", host)
	if err != nil {
		return fmt.Errorf("SOCKS5 监听失败: %w", err)
	}
	socks5Ln = ln

	ctx, cancel := context.WithCancel(context.Background())
	activeCtx, activeStop = ctx, cancel

	// ---- 连接池 ----
	clientID = uuid.NewString()
	pool := NewECHPool(forwardAddr, connectionNum, targetIPs, clientID)
	activePool = pool
	echPool = pool
	pool.Start()

	running = true

	// ---- 接受 SOCKS5 连接（原 runSOCKS5Listener 去掉 log.Fatalf 的版本）----
	go func() {
		cfgp := &ProxyConfig{"", "", host}
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// 非主动关闭导致的临时错误，稍等重试
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go handleSOCKS5(c, cfgp)
		}
	}()

	return nil
}

// WaitSocksProxyReady 等待至少一条通道就绪，超时返回 false。
func WaitSocksProxyReady(timeoutMs int) bool {
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for {
		serviceMu.Lock()
		p := activePool
		isRunning := running
		serviceMu.Unlock()

		if !isRunning || p == nil {
			return false
		}
		if p.Ready() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// StopSocksProxy 停止隧道并释放资源。
func StopSocksProxy() {
	serviceMu.Lock()
	defer serviceMu.Unlock()

	if !running {
		return
	}
	running = false

	if activeStop != nil {
		activeStop()
	}
	if socks5Ln != nil {
		_ = socks5Ln.Close()
		socks5Ln = nil
	}
	if activePool != nil {
		activePool.Close()
		activePool = nil
	}
	echPool = nil
}
