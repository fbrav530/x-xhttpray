package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// Android 客户端不使用 HTML 伪装（那是服务端功能），
// 移除 //go:embed 以避免依赖不存在的 index.html 导致编译失败。
var embeddedHTML []byte

type GlobalConfig struct {
	DialTimeout        time.Duration
	WSHandshakeTimeout time.Duration
	ReconnectDelay     time.Duration
	RTTProbeTimeout    time.Duration

	ReadBuf int
}

var cfg = GlobalConfig{
	DialTimeout:        3 * time.Second,
	WSHandshakeTimeout: 5 * time.Second,
	ReconnectDelay:     1 * time.Second,
	RTTProbeTimeout:    2 * time.Second,
	ReadBuf:            64 * 1024,
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 64*1024); return &b }}

// ======================== 全局参数 ========================

var (
	listenAddr       string
	forwardAddr      string
	ipAddr           string
	udpBlockPortsStr string
	certFile         string
	keyFile          string
	token            string
	cidrs            string
	connectionNum    int
	insecure         bool
	ips              string
	enableHtml       bool // 修改为布尔参数，决定是否启用内置 HTML

	dnsServer string
	echDomain string
	fallback  bool

	echListMu sync.RWMutex
	echList   []byte
	refreshMu sync.Mutex

	echPool *ECHPool

	clientID      string
	udpBlockPorts map[int]struct{}

	socks5Config *SOCKS5Config
	ipStrategy   byte
)

const (
	IPStrategyDefault  byte = 0
	IPStrategyIPv4Only byte = 1
	IPStrategyIPv6Only byte = 2
	IPStrategyPv4Pv6   byte = 3
	IPStrategyPv6Pv4   byte = 4
)

type SOCKS5Config struct {
	Host     string
	Username string
	Password string
}

// 默认值（原 init() 里的 flag 默认值，Android 上由绑定层参数覆盖）
func init() {
	udpBlockPortsStr = "443"
	cidrs = "0.0.0.0/0,::/0"
	dnsServer = "https://doh.pub/dns-query"
	echDomain = "cloudflare-ech.com"
	connectionNum = 3
}


func parseIPStrategy(s string) byte {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	switch s {
	case "4":
		return IPStrategyIPv4Only
	case "6":
		return IPStrategyIPv6Only
	case "4,6":
		return IPStrategyPv4Pv6
	case "6,4":
		return IPStrategyPv6Pv4
	default:
		return IPStrategyDefault
	}
}

// wsNetConn 已移除：传输层改为 xhttp（见 xhttp.go），
// 每条通道直接就是一个 net.Conn，不再需要 WebSocket 帧封装。

const (
	streamKindTCP  byte = 1
	streamKindUDP  byte = 2
	streamKindPing byte = 3
)

// ======================== SOCKS5 辅助函数 ========================

func parseSOCKS5Addr(addr string) (*SOCKS5Config, error) {
	addr = strings.TrimPrefix(addr, "socks5://")
	config := &SOCKS5Config{}

	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的SOCKS5地址格式")
		}
		auth := parts[0]
		if strings.Contains(auth, ":") {
			authParts := strings.SplitN(auth, ":", 2)
			config.Username = authParts[0]
			config.Password = authParts[1]
		}
		config.Host = parts[1]
	} else {
		config.Host = addr
	}
	return config, nil
}

func dialViaSocks5(network, addr string) (net.Conn, error) {
	if socks5Config == nil {
		return net.DialTimeout(network, addr, cfg.DialTimeout)
	}
	proxyConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("连接SOCKS5代理失败: %v", err)
	}
	if err := socks5Handshake(proxyConn, socks5Config); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5握手失败: %v", err)
	}
	if err := socks5Connect(proxyConn, addr); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT失败: %v", err)
	}
	return proxyConn, nil
}

func socks5Handshake(conn net.Conn, config *SOCKS5Config) error {
	var methods []byte
	if config.Username != "" && config.Password != "" {
		methods = []byte{0x00, 0x02}
	} else {
		methods = []byte{0x00}
	}
	greeting := make([]byte, 2+len(methods))
	greeting[0], greeting[1] = 0x05, byte(len(methods))
	copy(greeting[2:], methods)

	if _, err := conn.Write(greeting); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return fmt.Errorf("SOCKS 版本错误: %d", response[0])
	}
	switch response[1] {
	case 0x00:
		return nil
	case 0x02:
		return socks5UserPassAuthSrv(conn, config.Username, config.Password)
	case 0xFF:
		return errors.New("服务器不接受认证")
	default:
		return fmt.Errorf("认证方法错误: %d", response[1])
	}
}

func socks5UserPassAuthSrv(conn net.Conn, username, password string) error {
	authReq := make([]byte, 3+len(username)+len(password))
	authReq[0], authReq[1] = 0x01, byte(len(username))
	copy(authReq[2:], username)
	authReq[2+len(username)] = byte(len(password))
	copy(authReq[3+len(username):], password)

	if _, err := conn.Write(authReq); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return errors.New("认证失败")
	}
	return nil
}

func socks5Connect(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	var request []byte
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = make([]byte, 10)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x01
			copy(request[4:8], ip4)
			request[8], request[9] = byte(port>>8), byte(port)
		} else {
			request = make([]byte, 22)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x04
			copy(request[4:20], ip)
			request[20], request[21] = byte(port>>8), byte(port)
		}
	} else {
		request = make([]byte, 7+len(host))
		request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x03
		request[4] = byte(len(host))
		copy(request[5:], host)
		request[5+len(host)], request[6+len(host)] = byte(port>>8), byte(port)
	}

	if _, err := conn.Write(request); err != nil {
		return err
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return fmt.Errorf("状态码: %d", response[1])
	}
	switch response[3] {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 6))
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		_, _ = io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 18))
	}
	return nil
}

// ======================== UDP Relayer (服务端用) ========================

type UDPRelayer interface {
	Read(buffer []byte) (int, *net.UDPAddr, error)
	Write(data []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

type DirectUDPRelayer struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (d *DirectUDPRelayer) Read(buffer []byte) (int, *net.UDPAddr, error) {
	return d.conn.ReadFromUDP(buffer)
}
func (d *DirectUDPRelayer) Write(data []byte) (int, error)    { return d.conn.WriteToUDP(data, d.target) }
func (d *DirectUDPRelayer) SetReadDeadline(t time.Time) error { return d.conn.SetReadDeadline(t) }
func (d *DirectUDPRelayer) Close() error                      { return d.conn.Close() }

type SOCKS5UDPRelay struct {
	tcpConn    net.Conn
	udpConn    *net.UDPConn
	relayAddr  *net.UDPAddr
	targetAddr *net.UDPAddr
	mu         sync.Mutex
	closed     bool
}

func newSOCKS5UDPRelay(targetAddr string) (*SOCKS5UDPRelay, error) {
	if socks5Config == nil {
		return nil, errors.New("SOCKS5配置为空")
	}
	tcpConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, err
	}
	if err := socks5Handshake(tcpConn, socks5Config); err != nil {
		tcpConn.Close()
		return nil, err
	}
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE拒绝: %d", resp[1])
	}
	var relayHost string
	switch resp[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(tcpConn, ipBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(tcpConn, domainBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = string(domainBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(tcpConn, ipBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = net.IP(ipBuf).String()
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, portBuf); err != nil {
		tcpConn.Close()
		return nil, err
	}
	relayPort := int(portBuf[0])<<8 | int(portBuf[1])

	if relayHost == "0.0.0.0" || relayHost == "::" {
		h, _, _ := net.SplitHostPort(socks5Config.Host)
		relayHost = h
	}
	rAddr, errResolve := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", relayHost, relayPort))
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	tAddr, errResolve := net.ResolveUDPAddr("udp", targetAddr)
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	localUDP, errListen := net.ListenUDP("udp", nil)
	if errListen != nil {
		tcpConn.Close()
		return nil, errListen
	}

	log.Printf("[服务端UDP] SOCKS5 UDP中继: %s -> %s", rAddr, targetAddr)
	return &SOCKS5UDPRelay{
		tcpConn:    tcpConn,
		udpConn:    localUDP,
		relayAddr:  rAddr,
		targetAddr: tAddr,
	}, nil
}

func (r *SOCKS5UDPRelay) Write(data []byte) (int, error) {
	if r == nil || r.udpConn == nil || r.relayAddr == nil || r.targetAddr == nil {
		return 0, errors.New("SOCKS5 UDP relay 未初始化")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("closed")
	}
	pkt := buildSOCKS5UDPPacketData(r.targetAddr, data)
	return r.udpConn.WriteToUDP(pkt, r.relayAddr)
}

func (r *SOCKS5UDPRelay) Read(buffer []byte) (int, *net.UDPAddr, error) {
	if r == nil || r.udpConn == nil {
		return 0, nil, errors.New("SOCKS5 UDP relay 未初始化")
	}
	if r.closed {
		return 0, nil, errors.New("closed")
	}
	tmpPtr := bufPool.Get().(*[]byte)
	tmp := *tmpPtr
	defer bufPool.Put(tmpPtr)

	n, _, err := r.udpConn.ReadFromUDP(tmp)
	if err != nil {
		return 0, nil, err
	}
	srcAddr, payload, err := parseSOCKS5UDPResp(tmp[:n])
	if err != nil {
		return 0, nil, err
	}
	copy(buffer, payload)
	return len(payload), srcAddr, nil
}

func (r *SOCKS5UDPRelay) SetReadDeadline(t time.Time) error {
	if r == nil || r.udpConn == nil {
		return errors.New("SOCKS5 UDP relay 未初始化")
	}
	return r.udpConn.SetReadDeadline(t)
}

func (r *SOCKS5UDPRelay) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	_ = r.udpConn.Close()
	_ = r.tcpConn.Close()
	return nil
}

func buildSOCKS5UDPPacketData(target *net.UDPAddr, data []byte) []byte {
	packet := []byte{0x00, 0x00, 0x00}
	if ip4 := target.IP.To4(); ip4 != nil {
		packet = append(packet, 0x01)
		packet = append(packet, ip4...)
	} else {
		packet = append(packet, 0x04)
		packet = append(packet, target.IP...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(target.Port))
	packet = append(packet, portBytes...)
	packet = append(packet, data...)
	return packet
}

func parseSOCKS5UDPResp(packet []byte) (*net.UDPAddr, []byte, error) {
	if len(packet) < 10 {
		return nil, nil, fmt.Errorf("数据包过短")
	}
	atyp := packet[3]
	offset := 4
	var host string
	switch atyp {
	case 0x01:
		if offset+4 > len(packet) {
			return nil, nil, fmt.Errorf("IPv4地址长度过短")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 0x03:
		if offset+1 > len(packet) {
			return nil, nil, fmt.Errorf("域名长度字段过短")
		}
		l := int(packet[offset])
		offset++
		if offset+l > len(packet) {
			return nil, nil, fmt.Errorf("域名长度不足")
		}
		host = string(packet[offset : offset+l])
		offset += l
	case 0x04:
		if offset+16 > len(packet) {
			return nil, nil, fmt.Errorf("IPv6地址长度过短")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return nil, nil, fmt.Errorf("地址类型无效: %d", atyp)
	}
	if offset+2 > len(packet) {
		return nil, nil, fmt.Errorf("端口字段过短")
	}
	port := int(packet[offset])<<8 | int(packet[offset+1])
	offset += 2
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if addr == nil {
		return nil, nil, fmt.Errorf("解析地址失败")
	}
	return addr, packet[offset:], nil
}

// ======================== ECH 相关（客户端） ========================

const typeHTTPS = 65

func prepareECH() error {
	for {
		log.Printf("[客户端] DNS查询 ECH: %s -> %s", dnsServer, echDomain)
		echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS 查询失败: %v，重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到 ECH 参数，重试...")
			time.Sleep(2 * time.Second)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64 解码失败: %v，重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
		return nil
	}
}

func refreshECH() error {
	if fallback {
		return nil
	}

	refreshMu.Lock()
	defer refreshMu.Unlock()
	log.Printf("[客户端] 刷新 ECH 配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	if fallback {
		return nil, nil
	}
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		},
		RootCAs: roots,
	}, nil
}

func buildStandardTLSConfig(serverName string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure, // 修正：fallback/标准TLS也要支持 -insecure
	}, nil
}

func buildUnifiedTLSConfig(serverName string) (*tls.Config, error) {
	if fallback {
		return buildStandardTLSConfig(serverName)
	}
	ech, e := getECHList()
	if e != nil {
		return nil, e
	}
	cfgTLS, err := buildTLSConfigWithECH(serverName, ech)
	if err != nil {
		return nil, err
	}
	cfgTLS.InsecureSkipVerify = insecure
	return cfgTLS, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	if strings.HasPrefix(dnsServer, "http://") || strings.HasPrefix(dnsServer, "https://") {
		return queryDoH(domain, dnsServer)
	}
	return queryDNSUDP(domain, dnsServer)
}

func queryDNSUDP(domain, dnsServer string) (string, error) {
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	query := buildDNSQuery(domain, typeHTTPS)

	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("连接 DNS 服务器失败: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err = conn.Write(query); err != nil {
		return "", fmt.Errorf("发送查询失败: %v", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("DNS 查询超时")
		}
		return "", fmt.Errorf("读取 DNS 响应失败: %v", err)
	}
	return parseDNSResponse(response[:n])
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 状态码: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00)
	query = append(query, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("无答案记录")
	}
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)
		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket 服务端 ========================

var serverSessions sync.Map // map[string]*ClientSession

// WSChannel 一条“通道”现在对应一条 xhttp 逻辑连接（内部就是 GET 下行 + POST 上行）
type WSChannel struct {
	id      uint64
	conn    net.Conn
	session *ClientSession
}

type ClientSession struct {
	nextChanID uint64

	clientID string

	mu       sync.RWMutex
	channels map[uint64]*WSChannel
}

func getOrCreateClientSession(clientID string) *ClientSession {
	if v, ok := serverSessions.Load(clientID); ok {
		if cs, okType := v.(*ClientSession); okType && cs != nil {
			return cs
		}
		serverSessions.Delete(clientID)
	}
	s := &ClientSession{
		clientID: clientID,
		channels: make(map[uint64]*WSChannel),
	}
	actual, _ := serverSessions.LoadOrStore(clientID, s)
	if cs, ok := actual.(*ClientSession); ok && cs != nil {
		return cs
	}
	serverSessions.Store(clientID, s)
	return s
}

func (s *ClientSession) addChannel(wsConn net.Conn, preferredID uint64) *WSChannel {
	newID := preferredID
	if newID == 0 {
		newID = atomic.AddUint64(&s.nextChanID, 1)
	}
	ch := &WSChannel{
		id:      newID,
		conn:    wsConn,
		session: s,
	}
	var replaced *WSChannel
	s.mu.Lock()
	if old, ok := s.channels[ch.id]; ok {
		replaced = old
	}
	s.channels[ch.id] = ch
	s.mu.Unlock()
	if replaced != nil {
		_ = replaced.conn.Close()
	}
	return ch
}

func (s *ClientSession) removeChannel(id uint64, current *WSChannel) {
	s.mu.Lock()
	if ch, ok := s.channels[id]; ok && ch == current {
		delete(s.channels, id)
	}
	empty := len(s.channels) == 0
	s.mu.Unlock()

	if empty {
		log.Printf("[服务端] 客户端会话 %s 断开", s.clientID)
		serverSessions.Delete(s.clientID)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"SelfSigned"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
	)
}

func runWebSocketServer(addr string) {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatalf("[服务端] 监听地址无效: %v", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	var allowedNets []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		_, allowedNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			log.Fatalf("[服务端] CIDR 解析失败: %v", err)
		}
		allowedNets = append(allowedNets, allowedNet)
	}

	// xhttp 传输：GET 下行 + POST 上行，sessionId/seq 默认走路径
	xcfg := xhttpServerConfig(path)
	xl := NewXHTTPListener(xcfg)
	// 下行 GET 建立后，把连接登记为本通道
	xl.SetConnCallback(func(c net.Conn) {
		cid, chID := "anonymous", uint64(0)
		if sc, ok := c.(*xhttpServerConn); ok {
			if sc.clientID != "" {
				cid = sc.clientID
			}
			chID = sc.channelID
		}
		session := getOrCreateClientSession(cid)
		ch := session.addChannel(c, chID)
		log.Printf("[服务端] 客户端通道 %d 连接, 客户端ID: %s", ch.id, shortID(cid))
		go handleWebSocketChannel(ch)
	})

	// 拦截所有请求：xhttp 握手走传输，其余交给 HTML 伪装 / 400 / 404
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 1. xhttp 请求：先做来源校验，再交给传输层
		if strings.HasPrefix(r.URL.Path, xcfg.basePath()) {
			clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "错误的请求", http.StatusBadRequest)
				return
			}
			ip := net.ParseIP(clientIP)
			allowed := false
			for _, n := range allowedNets {
				if n.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "禁止访问", http.StatusForbidden)
				return
			}
			if token != "" {
				got := r.Header.Get("X-Token")
				if got == "" {
					got = r.URL.Query().Get("token")
				}
				if got != token {
					log.Printf("[服务端] Token 认证失败，来源 IP: %s", clientIP)
					http.Error(w, "未授权", http.StatusUnauthorized)
					return
				}
			}
			xl.ServeHTTP(w, r)
			return
		}

		// 2. 伪装 HTML
		if enableHtml {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(embeddedHTML)
			return
		}

		// 3. 路径对上了但不是合法请求
		if r.URL.Path == path {
			http.Error(w, "未授权", http.StatusBadRequest)
			return
		}

		// 4. 其他路径
		http.NotFound(w, r)
	})

	if u.Scheme == "wss" {
		server := &http.Server{Addr: u.Host}
		if certFile != "" && keyFile != "" {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
				log.Fatalf("[服务端] WSS 启动失败: %v", err)
			}
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("[服务端] 生成自签名证书失败: %v", err)
			}
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			log.Printf("[服务端] WSS 启动 %s%s", u.Host, path)
			if err := server.ListenAndServeTLS("", ""); err != nil {
				log.Fatalf("[服务端] WSS 启动失败: %v", err)
			}
		}
	} else {
		log.Printf("[服务端] WS 启动 %s%s", u.Host, path)
		if err := http.ListenAndServe(u.Host, nil); err != nil {
			log.Fatalf("[服务端] WS 启动失败: %v", err)
		}
	}
}

// 根据 IP 策略拨号 TCP
func dialTCPWithStrategy(addr string, strategy byte) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return net.DialTimeout("tcp", addr, cfg.DialTimeout)
	}

	if ip := net.ParseIP(host); ip != nil {
		return net.DialTimeout("tcp", addr, cfg.DialTimeout)
	}

	if strategy == IPStrategyIPv4Only {
		return net.DialTimeout("tcp4", addr, cfg.DialTimeout)
	}
	if strategy == IPStrategyIPv6Only {
		return net.DialTimeout("tcp6", addr, cfg.DialTimeout)
	}

	if strategy == IPStrategyPv4Pv6 || strategy == IPStrategyPv6Pv4 {
		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		var v4, v6 net.IP
		for _, a := range addrs {
			if a.IP.To4() != nil {
				if v4 == nil {
					v4 = a.IP
				}
			} else {
				if v6 == nil {
					v6 = a.IP
				}
			}
			if v4 != nil && v6 != nil {
				break
			}
		}

		var selected net.IP
		if strategy == IPStrategyPv4Pv6 {
			if v4 != nil {
				selected = v4
			} else {
				selected = v6
			}
		} else {
			if v6 != nil {
				selected = v6
			} else {
				selected = v4
			}
		}

		if selected == nil {
			return nil, fmt.Errorf("未找到可用IP: %s", host)
		}

		target := net.JoinHostPort(selected.String(), port)
		return net.DialTimeout("tcp", target, cfg.DialTimeout)
	}

	return net.DialTimeout("tcp", addr, cfg.DialTimeout)
}

func resolveUDPWithStrategy(addr string, strategy byte) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ResolveUDPAddr("udp", addr)
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	if strategy == IPStrategyIPv4Only {
		return net.ResolveUDPAddr("udp4", addr)
	}
	if strategy == IPStrategyIPv6Only {
		return net.ResolveUDPAddr("udp6", addr)
	}

	if strategy == IPStrategyPv4Pv6 || strategy == IPStrategyPv6Pv4 {
		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		var v4, v6 net.IP
		for _, a := range addrs {
			if a.IP.To4() != nil {
				if v4 == nil {
					v4 = a.IP
				}
			} else {
				if v6 == nil {
					v6 = a.IP
				}
			}
			if v4 != nil && v6 != nil {
				break
			}
		}

		var selected net.IP
		if strategy == IPStrategyPv4Pv6 {
			if v4 != nil {
				selected = v4
			} else {
				selected = v6
			}
		} else {
			if v6 != nil {
				selected = v6
			} else {
				selected = v4
			}
		}

		if selected == nil {
			return nil, fmt.Errorf("未找到可用IP: %s", host)
		}
		return &net.UDPAddr{IP: selected, Port: port}, nil
	}

	return net.ResolveUDPAddr("udp", addr)
}

// ======================== WebSocket 处理逻辑 ========================

func handleWebSocketChannel(ch *WSChannel) {
	wsConn := ch.conn
	session := ch.session

	defer func() {
		_ = wsConn.Close()
		session.removeChannel(ch.id, ch)
	}()
	netConn := wsConn
	sess, err := smux.Server(netConn, nil)
	if err != nil {
		log.Printf("[服务端] 通道 %d smux 初始化失败: %v", ch.id, err)
		return
	}
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("[服务端] 客户端通道 %d 断开", ch.id)
			return
		}
		go handleSmuxStream(session, ch, stream)
	}
}

func readSmuxOpenHeader(r io.Reader) (byte, byte, string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, 0, "", err
	}
	kind := head[0]
	strategy := head[1]
	targetLen := int(binary.BigEndian.Uint16(head[2:4]))
	targetRaw := make([]byte, targetLen)
	if targetLen > 0 {
		if _, err := io.ReadFull(r, targetRaw); err != nil {
			return 0, 0, "", err
		}
	}
	return kind, strategy, string(targetRaw), nil
}

func handleSmuxStream(session *ClientSession, ch *WSChannel, stream *smux.Stream) {
	defer stream.Close()
	kind, strategy, target, err := readSmuxOpenHeader(stream)
	if err != nil {
		return
	}
	switch kind {
	case streamKindPing:
		payload := make([]byte, 8)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return
		}
		_, _ = stream.Write(payload)
	case streamKindTCP:
		log.Printf("[服务端] 客户ID:%s TCP 打开: %s, 通道:%d", shortID(session.clientID), target, ch.id)
		var tcpConn net.Conn
		if socks5Config != nil {
			tcpConn, err = dialViaSocks5("tcp", target)
		} else {
			tcpConn, err = dialTCPWithStrategy(target, strategy)
		}
		if err != nil {
			return
		}
		proxyConnStream(tcpConn, stream)
		log.Printf("[服务端] 客户ID:%s TCP 关闭: %s, 通道:%d", shortID(session.clientID), target, ch.id)
	case streamKindUDP:
		log.Printf("[服务端] 客户ID:%s SOCKS5 UDP 访问: %s, 通道:%d", shortID(session.clientID), target, ch.id)
		var relay UDPRelayer
		if socks5Config != nil {
			var socksRelay *SOCKS5UDPRelay
			socksRelay, err = newSOCKS5UDPRelay(target)
			if err != nil {
				log.Printf("[服务端] 客户ID:%s SOCKS5 UDP中继创建失败: %v, 通道:%d", shortID(session.clientID), err, ch.id)
				return
			}
			relay = socksRelay
		} else {
			addr, errResolve := resolveUDPWithStrategy(target, strategy)
			if errResolve != nil {
				return
			}
			udpConn, errListen := net.ListenUDP("udp", nil)
			if errListen != nil {
				return
			}
			relay = &DirectUDPRelayer{conn: udpConn, target: addr}
		}
		if relay == nil {
			return
		}
		defer relay.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				packet, e := readChunk(stream)
				if e != nil {
					return
				}
				if len(packet) == 0 {
					continue
				}
				if _, e = relay.Write(packet); e != nil {
					return
				}
			}
		}()
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		defer bufPool.Put(bufPtr)
		for {
			_ = relay.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, e := relay.Read(buf)
			if e != nil {
				if netErr, ok := e.(net.Error); ok && netErr.Timeout() {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				return
			}
			if err := writeUDPReply(stream, addr.String(), buf[:n]); err != nil {
				return
			}
		}
	}
}

// ======================== 多通道客户端池 ========================

type ECHPool struct {
	wsServerAddr  string
	connectionNum int
	targetIPs     []string
	clientID      string

	// 用于优雅停止：Close 时 cancel，dialAndServe 退出重连循环
	ctx    context.Context
	cancel context.CancelFunc

	wsConnsMu     sync.RWMutex
	smuxConns     []*smux.Session
	channelRTT    []int64
	selectCounter uint64
}

func NewECHPool(addr string, n int, ips []string, clientID string) *ECHPool {
	total := n
	if len(ips) > 0 {
		total = len(ips) * n
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &ECHPool{
		wsServerAddr:  addr,
		connectionNum: n,
		targetIPs:     ips,
		clientID:      clientID,
		ctx:           ctx,
		cancel:        cancel,
		smuxConns:     make([]*smux.Session, total),
		channelRTT:    make([]int64, total),
	}
	return p
}

// Close 停止所有重连循环并关闭已建立的会话。
// 原版本没有这个方法，Android 上无法安全停止隧道，故新增。
func (p *ECHPool) Close() {
	if p == nil {
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	p.wsConnsMu.Lock()
	sessions := make([]*smux.Session, len(p.smuxConns))
	copy(sessions, p.smuxConns)
	for i := range p.smuxConns {
		p.smuxConns[i] = nil
	}
	p.wsConnsMu.Unlock()
	for _, s := range sessions {
		if s != nil {
			_ = s.Close()
		}
	}
}

// Ready 报告是否至少有一条可用通道（不创建流，仅检查会话状态）。
func (p *ECHPool) Ready() bool {
	if p == nil {
		return false
	}
	p.wsConnsMu.RLock()
	defer p.wsConnsMu.RUnlock()
	for _, sess := range p.smuxConns {
		if sess != nil && !sess.IsClosed() {
			return true
		}
	}
	return false
}

func (p *ECHPool) Start() {
	for i := 0; i < len(p.smuxConns); i++ {
		ip := ""
		if len(p.targetIPs) > 0 {
			if idx := i / p.connectionNum; idx < len(p.targetIPs) {
				ip = p.targetIPs[idx]
			}
		}
		go p.dialAndServe(i, ip)
	}
}

func (p *ECHPool) dialAndServe(idx int, ip string) {
	chID := idx + 1
	ipLabel := ip
	if strings.TrimSpace(ipLabel) == "" {
		ipLabel = "自动解析"
	}
	for {
		// 可停止：Close() 后不再重连
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		wsConn, err := dialXHTTPChannel(p.wsServerAddr, 3, ip, p.clientID, chID)
		if err != nil {
			log.Printf("[客户端] 通道 %d (IP:%s) 连接失败: %v", chID, ipLabel, err)
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}
		wsNet := wsConn
		sess, err := smux.Client(wsNet, nil)
		if err != nil {
			_ = wsConn.Close()
			log.Printf("[客户端] 通道 %d (IP:%s) smux 初始化失败: %v", chID, ipLabel, err)
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(cfg.ReconnectDelay):
			}
			continue
		}
		p.wsConnsMu.Lock()
		p.smuxConns[idx] = sess
		p.channelRTT[idx] = 0
		p.wsConnsMu.Unlock()
		log.Printf("[客户端] 通道 %d (IP:%s) 就绪 (xhttp/smux)", chID, ipLabel)
		if rtt, err := p.probeChannelRTTOnce(sess, cfg.RTTProbeTimeout); err == nil {
			atomic.StoreInt64(&p.channelRTT[idx], rtt)
		}

		done := make(chan error, 1)
		go p.probeChannelRTT(sess, idx, done)
		var probeErr error
		select {
		case probeErr = <-done:
		case <-wsNet.Dead():
			_ = sess.Close()
			<-done
			probeErr = wsNet.DeadErr()
			if probeErr == nil {
				probeErr = io.EOF
			}
		}

		_ = sess.Close()
		_ = wsConn.Close()

		p.wsConnsMu.Lock()
		p.smuxConns[idx] = nil
		p.channelRTT[idx] = 0
		p.wsConnsMu.Unlock()
		if probeErr != nil {
			log.Printf("[客户端] 通道 %d 断开原因: %v", chID, probeErr)
		}
		select {
		case <-p.ctx.Done():
			log.Printf("[客户端] 通道 %d 已停止", chID)
			return
		default:
		}
		log.Printf("[客户端] 通道 %d 断开，重连中...", chID)
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(cfg.ReconnectDelay):
		}
	}
}

func (p *ECHPool) probeChannelRTT(sess *smux.Session, idx int, done chan error) {
	var exitErr error
	defer func() {
		done <- exitErr
		close(done)
	}()
	ticker := time.NewTicker(cfg.RTTProbeTimeout)
	defer ticker.Stop()
	for {
		rtt, err := p.probeChannelRTTOnce(sess, cfg.RTTProbeTimeout)
		if err != nil {
			atomic.StoreInt64(&p.channelRTT[idx], int64(cfg.RTTProbeTimeout.Nanoseconds()))
			if sess.IsClosed() {
				exitErr = err
				return
			}
			<-ticker.C
			continue
		}
		atomic.StoreInt64(&p.channelRTT[idx], rtt)
		<-ticker.C
	}
}

func (p *ECHPool) probeChannelRTTOnce(sess *smux.Session, timeout time.Duration) (int64, error) {
	start := time.Now()
	s, err := sess.OpenStream()
	if err != nil {
		return 0, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))
	if err := writeSmuxOpenHeader(s, streamKindPing, 0, ""); err != nil {
		return 0, err
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))
	if _, err := s.Write(payload); err != nil {
		return 0, err
	}
	ack := make([]byte, 8)
	if _, err := io.ReadFull(s, ack); err != nil {
		return 0, err
	}
	if !bytes.Equal(ack, payload) {
		return 0, fmt.Errorf("ping ack mismatch")
	}
	return time.Since(start).Nanoseconds(), nil
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func proxyConnStream(c net.Conn, stream *smux.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(stream, c)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, stream)
		done <- struct{}{}
	}()
	<-done

	// 立即关闭双方，强制中断另一方向的 io.Copy
	_ = stream.Close()
	_ = c.Close()

	<-done // 等待另一方向退出
}

func clientSourceAddr(c net.Conn) string {
	if ra := c.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return "-"
}

func logClientConnEvent(c net.Conn, reqType, target string, chID int, opened bool) {
	arrow := "关闭"
	if opened {
		arrow = "打开"
	}
	log.Printf("[客户端] %s %s %s %s 通道 %d", clientSourceAddr(c), reqType, arrow, target, chID)
}

func (p *ECHPool) openBestStream() (*smux.Stream, int, int, error) {
	p.wsConnsMu.RLock()
	type candidate struct {
		idx int
		rtt int64
	}
	cands := make([]candidate, 0, len(p.smuxConns))
	for i, sess := range p.smuxConns {
		if sess == nil || sess.IsClosed() {
			continue
		}
		rtt := atomic.LoadInt64(&p.channelRTT[i])
		if rtt <= 0 {
			rtt = int64(cfg.RTTProbeTimeout.Nanoseconds())
		}
		cands = append(cands, candidate{idx: i, rtt: rtt})
	}
	p.wsConnsMu.RUnlock()
	if len(cands) == 0 {
		return nil, 0, 0, fmt.Errorf("无可用 smux 通道")
	}
	minRTT := cands[0].rtt
	for _, c := range cands[1:] {
		if c.rtt < minRTT {
			minRTT = c.rtt
		}
	}
	tieWindow := int64((10 * time.Millisecond).Nanoseconds())
	near := make([]candidate, 0, len(cands))
	for _, c := range cands {
		if c.rtt <= minRTT+tieWindow {
			near = append(near, c)
		}
	}
	pick := int(atomic.AddUint64(&p.selectCounter, 1)-1) % len(near)
	best := near[pick]
	p.wsConnsMu.RLock()
	sess := p.smuxConns[best.idx]
	p.wsConnsMu.RUnlock()
	if sess == nil || sess.IsClosed() {
		return nil, 0, 0, fmt.Errorf("通道不可用")
	}
	decision := best.idx + 1
	s, err := sess.OpenStream()
	if err != nil {
		return nil, 0, 0, err
	}
	return s, best.idx + 1, decision, nil
}

func writeSmuxOpenHeader(w io.Writer, kind byte, strategy byte, target string) error {
	if len(target) > 65535 {
		return fmt.Errorf("目标地址过长")
	}
	head := make([]byte, 4)
	head[0] = kind
	head[1] = strategy
	binary.BigEndian.PutUint16(head[2:4], uint16(len(target)))
	if _, err := w.Write(head); err != nil {
		return err
	}
	if len(target) == 0 {
		return nil
	}
	_, err := w.Write([]byte(target))
	return err
}

func (p *ECHPool) openTCPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindTCP, ipStrategy, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	return s, chID, decision, nil
}

func (p *ECHPool) openUDPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindUDP, ipStrategy, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	return s, chID, decision, nil
}

func writeChunk(w io.Writer, b []byte) error {
	if len(b) > 65535 {
		return fmt.Errorf("数据块过大")
	}
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(len(b)))
	if _, err := w.Write(h); err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	_, err := w.Write(b)
	return err
}

func readChunk(r io.Reader) ([]byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h))
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeUDPReply(w io.Writer, addr string, payload []byte) error {
	if len(addr) > 65535 {
		return fmt.Errorf("地址过长")
	}
	head := make([]byte, 4)
	binary.BigEndian.PutUint16(head[0:2], uint16(len(addr)))
	binary.BigEndian.PutUint16(head[2:4], uint16(len(payload)))
	if _, err := w.Write(head); err != nil {
		return err
	}
	if len(addr) > 0 {
		if _, err := w.Write([]byte(addr)); err != nil {
			return err
		}
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readUDPReply(r io.Reader) (string, []byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", nil, err
	}
	addrLen := int(binary.BigEndian.Uint16(head[0:2]))
	dataLen := int(binary.BigEndian.Uint16(head[2:4]))
	addrRaw := make([]byte, addrLen)
	if addrLen > 0 {
		if _, err := io.ReadFull(r, addrRaw); err != nil {
			return "", nil, err
		}
	}
	data := make([]byte, dataLen)
	if dataLen > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return "", nil, err
		}
	}
	return string(addrRaw), data, nil
}

// ======================== TCP Forwarder ========================

func runTCPListener(rule string) {
	rule = strings.TrimPrefix(rule, "tcp://")
	parts := strings.Split(rule, "/")
	if len(parts) != 2 {
		return
	}
	lAddr, tAddr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	l, err := net.Listen("tcp", lAddr)
	if err != nil {
		log.Fatalf("[客户端] TCP监听失败: %v", err)
	}
	log.Printf("[客户端] TCP转发: %s -> %s", lAddr, tAddr)
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleLocalTCP(c, tAddr)
	}
}

func handleLocalTCP(c net.Conn, target string) {
	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		_ = c.Close()
		return
	}
	logClientConnEvent(c, "TCP转发", target, decision, true)
	defer logClientConnEvent(c, "TCP转发", target, decision, false)
	proxyConnStream(c, stream)
}

// dialXHTTPChannel：建立一条 xhttp 通道（GET 下行 + POST 上行）
// 原 ws/wss 语义保持不变：ws -> 明文 HTTP，wss -> TLS 1.3 + ECH
func dialXHTTPChannel(addr string, retries int, ip string, clientID string, channelID int) (*xhttpNetConn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "wss" && scheme != "ws" {
		return nil, fmt.Errorf("仅支持 ws:// 或 wss:// (当前: %s)", u.Scheme)
	}

	xcfg := xhttpClientConfig(channelID)
	xcfg.Token = token
	xcfg.ClientID = clientID

	// ws：明文
	if scheme == "ws" {
		conn, err := dialXHTTP(addr, xcfg, nil, ip)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	// wss：TLS 1.3 + ECH
	serverName := u.Hostname()
	for i := 1; i <= retries; i++ {
		tlsCfg, e := buildUnifiedTLSConfig(serverName)
		if e != nil {
			if i < retries {
				_ = refreshECH()
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, e
		}
		conn, err := dialXHTTP(addr, xcfg, tlsCfg, ip)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "HTTP 401") {
				return nil, fmt.Errorf("认证失败：Token 不匹配或未提供")
			}
			if !fallback && (strings.Contains(msg, "ECH") || strings.Contains(msg, "ech")) && i < retries {
				_ = refreshECH()
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, err
		}
		return conn, nil
	}
	return nil, fmt.Errorf("连接失败")
}

// xhttpClientConfig 客户端 xhttp 参数（与原版行为对齐：每通道一条独立逻辑流）
func xhttpClientConfig(channelID int) *XHTTPConfig {
	c := defaultXHTTPConfig()
	c.Mode = xhttpModePacketUp
	// 与原版“一条通道一个会话”一致：sessionId 由传输层自动生成
	c.XPaddingObfs = false
	c.ChannelID = channelID
	return c
}

// xhttpServerConfig 服务端 xhttp 参数；path 来自 -l 的地��路径
func xhttpServerConfig(path string) *XHTTPConfig {
	c := defaultXHTTPConfig()
	c.Mode = xhttpModePacketUp
	c.Path = path
	return c
}

// ======================== SOCKS5 / HTTP Proxy ========================

type ProxyConfig struct {
	Username, Password, Host string
}

type UDPAssociation struct {
	tcpConn       net.Conn
	udpListener   *net.UDPConn
	clientUDPAddr *net.UDPAddr
	pool          *ECHPool

	mu        sync.Mutex
	closed    bool
	receiving bool
	channelID int
	target    string
	stream    *smux.Stream
}

func parseAuthAndAddr(full string) (string, string, string, error) {
	u, p, h := "", "", full
	if strings.Contains(full, "@") {
		parts := strings.SplitN(full, "@", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("格式错误")
		}
		auth := parts[0]
		if strings.Contains(auth, ":") {
			ap := strings.SplitN(auth, ":", 2)
			u, p = ap[0], ap[1]
		}
		h = parts[1]
	}
	return h, u, p, nil
}

func runSOCKS5Listener(addr string) {
	h, u, p, err := parseAuthAndAddr(strings.TrimPrefix(addr, "socks5://"))
	if err != nil {
		log.Fatalf("[客户端] SOCKS5地址解析失败: %v", err)
	}
	l, err := net.Listen("tcp", h)
	if err != nil {
		log.Fatalf("[客户端] SOCKS5监听失败: %v", err)
	}
	log.Printf("[客户端] SOCKS5 代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5(c, cfgp)
	}
}

func handleSOCKS5(c net.Conn, cfgp *ProxyConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(cfg.DialTimeout))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 0x05 {
		return
	}
	methods := make([]byte, buf[1])
	_, _ = io.ReadFull(c, methods)
	if cfgp.Username != "" {
		_, _ = c.Write([]byte{0x05, 0x02})
		if err := handleSOCKS5UserPassAuth(c, cfgp); err != nil {
			return
		}
	} else {
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	var target string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
		target = net.IP(b).String()
	case 0x03:
		b := make([]byte, 1)
		_, _ = io.ReadFull(c, b)
		addr := make([]byte, b[0])
		_, _ = io.ReadFull(c, addr)
		target = string(addr)
	case 0x04:
		b := make([]byte, 16)
		_, _ = io.ReadFull(c, b)
		target = net.IP(b).String()
	}
	pb := make([]byte, 2)
	_, _ = io.ReadFull(c, pb)
	port := int(pb[0])<<8 | int(pb[1])
	target = net.JoinHostPort(target, fmt.Sprintf("%d", port))

	// 增强过滤逻辑：解析 host 判断是否为 IP，从而覆盖 ATYP=0x03 但内容为 IP 的情况
	host, _, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host)

	if head[1] == 0x01 {
		if ipStrategy == IPStrategyIPv4Only {
			if head[3] == 0x04 || (ip != nil && ip.To4() == nil) {
				_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
		}
		if ipStrategy == IPStrategyIPv6Only {
			if head[3] == 0x01 || (ip != nil && ip.To4() != nil) {
				_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
		}
	}

	_ = c.SetDeadline(time.Time{})

	switch head[1] {
	case 0x01:
		handleSOCKS5Connect(c, target)
	case 0x03:
		handleSOCKS5UDP(c, cfgp)
	}
}

func handleSOCKS5UserPassAuth(c net.Conn, cfgp *ProxyConfig) error {
	b := make([]byte, 2)
	_, _ = io.ReadFull(c, b)
	u := make([]byte, b[1])
	_, _ = io.ReadFull(c, u)
	_, _ = io.ReadFull(c, b[:1])
	p := make([]byte, b[0])
	_, _ = io.ReadFull(c, p)
	if string(u) == cfgp.Username && string(p) == cfgp.Password {
		_, _ = c.Write([]byte{0x01, 0x00})
		return nil
	}
	_, _ = c.Write([]byte{0x01, 0x01})
	return errors.New("认证失败")
}

func handleSOCKS5Connect(c net.Conn, target string) {
	_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		_ = c.Close()
		return
	}
	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		_ = c.Close()
		return
	}
	logClientConnEvent(c, "SOCKS5", target, decision, true)
	defer logClientConnEvent(c, "SOCKS5", target, decision, false)
	proxyConnStream(c, stream)
}

func handleSOCKS5UDP(c net.Conn, cfgp *ProxyConfig) {
	host, _, _ := net.SplitHostPort(cfgp.Host)
	uAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	ul, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		_ = c.Close()
		return
	}
	defer ul.Close()

	actual, ok := ul.LocalAddr().(*net.UDPAddr)
	if !ok || actual == nil {
		_ = c.Close()
		return
	}
	resp := []byte{0x05, 0x00, 0x00}
	if ip4 := actual.IP.To4(); ip4 != nil {
		resp = append(resp, 0x01)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, 0x04)
		resp = append(resp, actual.IP...)
	}
	resp = append(resp, byte(actual.Port>>8), byte(actual.Port))
	if _, err := c.Write(resp); err != nil {
		_ = c.Close()
		return
	}

	assoc := &UDPAssociation{
		tcpConn:     c,
		udpListener: ul,
		pool:        echPool,
		channelID:   -1,
	}

	go assoc.loop()
	b := make([]byte, 1)
	for {
		if _, err := c.Read(b); err != nil {
			assoc.Close()
			return
		}
	}
}

func (a *UDPAssociation) loop() {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		n, addr, err := a.udpListener.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		if a.clientUDPAddr == nil {
			a.clientUDPAddr = addr
		} else if a.clientUDPAddr.String() != addr.String() {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()

		tgt, data, err := parseSOCKS5UDPPacket(buf[:n])
		if err == nil {
			h, ps, _ := net.SplitHostPort(tgt)
			if ip := net.ParseIP(h); ip != nil {
				if ipStrategy == IPStrategyIPv4Only && ip.To4() == nil {
					continue
				}
				if ipStrategy == IPStrategyIPv6Only && ip.To4() != nil {
					continue
				}
			}
			var prt int
			_, _ = fmt.Sscanf(ps, "%d", &prt)
			if _, ok := udpBlockPorts[prt]; ok {
				continue
			}
			a.send(tgt, data)
		}
	}
}

func (a *UDPAssociation) send(target string, data []byte) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	needStart := !a.receiving
	if needStart {
		a.receiving = true
		a.target = target
	}
	stream := a.stream
	a.mu.Unlock()

	if needStart {
		s, id, decision, err := a.pool.openUDPStream(target)
		if err != nil {
			a.Close()
			return
		}
		a.mu.Lock()
		a.stream = s
		a.channelID = id
		stream = s
		a.mu.Unlock()
		logClientConnEvent(a.tcpConn, "SOCKS5-UDP", target, decision, true)
		go func() {
			for {
				addrStr, payload, e := readUDPReply(s)
				if e != nil {
					a.Close()
					return
				}
				a.handleUDPResponse(addrStr, payload)
			}
		}()
	} else {
		if target != "" && target != a.target {
			a.mu.Lock()
			a.target = target
			a.mu.Unlock()
		}
	}
	if stream == nil {
		a.Close()
		return
	}
	if err := writeChunk(stream, data); err != nil {
		a.Close()
	}
}

func (a *UDPAssociation) handleUDPResponse(addrStr string, data []byte) {
	host, portStr, _ := net.SplitHostPort(addrStr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	pkt, _ := buildSOCKS5UDPPacket(host, port, data)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientUDPAddr != nil {
		_, _ = a.udpListener.WriteToUDP(pkt, a.clientUDPAddr)
	}
}

func (a *UDPAssociation) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	stream := a.stream
	target := a.target
	chID := a.channelID
	a.closed = true
	a.stream = nil
	a.mu.Unlock()
	if stream != nil {
		_ = stream.Close()
	}
	if chID > 0 && target != "" {
		logClientConnEvent(a.tcpConn, "SOCKS5-UDP", target, chID, false)
	}
	_ = a.udpListener.Close()
	if a.tcpConn != nil {
		_ = a.tcpConn.Close()
	}
}

func parseSOCKS5UDPPacket(b []byte) (string, []byte, error) {
	if len(b) < 10 || b[2] != 0 {
		return "", nil, errors.New("数据不合法")
	}
	off := 4
	var h string
	switch b[3] {
	case 0x01:
		if off+4 > len(b) {
			return "", nil, errors.New("IPv4地址长度过短")
		}
		h = net.IP(b[off : off+4]).String()
		off += 4
	case 0x03:
		if off+1 > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		l := int(b[off])
		off++
		if off+l > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		h = string(b[off : off+l])
		off += l
	case 0x04:
		if off+16 > len(b) {
			return "", nil, errors.New("IPv6地址长度过短")
		}
		h = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return "", nil, errors.New("地址类型无效")
	}
	if off+2 > len(b) {
		return "", nil, errors.New("端口字段过短")
	}
	p := int(b[off])<<8 | int(b[off+1])
	off += 2
	t := fmt.Sprintf("%s:%d", h, p)
	if b[3] == 0x04 {
		t = fmt.Sprintf("[%s]:%d", h, p)
	}
	return t, b[off:], nil
}

func buildSOCKS5UDPPacket(h string, p int, d []byte) ([]byte, error) {
	buf := []byte{0, 0, 0}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, 0x04)
		buf = append(buf, ip...)
	} else {
		buf = append(buf, 0x03, byte(len(h)))
		buf = append(buf, h...)
	}
	buf = append(buf, byte(p>>8), byte(p))
	buf = append(buf, d...)
	return buf, nil
}

func runHTTPListener(addr string) {
	h, u, p, _ := parseAuthAndAddr(strings.TrimPrefix(addr, "http://"))
	l, err := net.Listen("tcp", h)
	if err != nil {
		log.Fatalf("[客户端] HTTP监听失败: %v", err)
	}
	log.Printf("[客户端] HTTP 代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleHTTP(c, cfgp)
	}
}

func handleHTTP(c net.Conn, cfgp *ProxyConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(cfg.DialTimeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	if cfgp.Username != "" {
		auth := req.Header.Get("Proxy-Authorization")
		ok := false
		if strings.HasPrefix(auth, "Basic ") {
			p, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
			pair := strings.SplitN(string(p), ":", 2)
			if len(pair) == 2 && pair[0] == cfgp.Username && pair[1] == cfgp.Password {
				ok = true
			}
		}
		if !ok {
			_, _ = c.Write([]byte("HTTP/1.1 407 需要认证\r\nProxy-Authenticate: Basic realm=\"代理\"\r\n\r\n"))
			return
		}
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	var first []byte

	if req.Method == "CONNECT" {
		_, _ = c.Write([]byte("HTTP/1.1 200 连接已建立\r\n\r\n"))
	} else {
		req.RequestURI = ""
		req.URL.Scheme = ""
		req.URL.Host = ""
		var buf bytes.Buffer
		_ = req.Write(&buf)
		first = buf.Bytes()
	}

	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		return
	}
	if len(first) > 0 {
		if _, err := stream.Write(first); err != nil {
			_ = stream.Close()
			return
		}
	}
	logClientConnEvent(c, "HTTP", target, decision, true)
	defer logClientConnEvent(c, "HTTP", target, decision, false)
	proxyConnStream(c, stream)
}


// ============================================================
// ==================== XHTTP 传输层实现 ======================
// ============================================================

// xhttp.go —— Xray 标准 XHTTP（原 SplitHTTP）传输实现
//
// 协议依据 Xray-core transport/internet/splithttp：
//   - 一份逻辑双工流被拆成两类 HTTP 请求：
//       上行 Uplink   : POST（packet-up 为多次短 POST，stream-up 为单次长 POST）
//       下行 Downlink : GET，响应体持续流出
//   - 两者用同一个 sessionId 关联；packet-up 模式下每个 POST 带单调递增 seq，
//     服务端按 seq 重排（Xray 侧 upload_queue.go 的 min-heap）。
//   - sessionId / seq / x_padding 的位置可配置：path | query | header | cookie。
//   - 上行 POST 体就是裸字节流，不额外加任何帧头。
//
// 本文件只负责「传输层」，上层仍在用原来的 smux + streamKind 帧格式，
// 因此服务端与客户端必须同时使用本实现。


// ======================== 配置 ========================

const (
	xhttpModePacketUp  = "packet-up"
	xhttpModeStreamUp  = "stream-up"
	xhttpModeStreamOne = "stream-one"
	xhttpModeAuto      = "auto"

	xhttpPlacementPath   = "path"
	xhttpPlacementQuery  = "query"
	xhttpPlacementHeader = "header"
	xhttpPlacementCookie = "cookie"
)

type xhttpRange struct {
	From int
	To   int
}

func (r xhttpRange) rand() int {
	if r.To <= r.From {
		return r.From
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(r.To-r.From+1)))
	if err != nil {
		return r.From
	}
	return r.From + int(n.Int64())
}

type XHTTPConfig struct {
	Mode   string // packet-up（默认）| stream-up | stream-one | auto
	Host   string // Host 头（留空则用地址里的主机名）
	Path   string // 基础路径，可带 ?query
	Method string // 上行方法，默认 POST

	// 上行切分控制
	ScMaxEachPostBytes   xhttpRange // 单个 POST 上限，默认 1MB
	ScMinPostsIntervalMs xhttpRange // POST 最小间隔，默认 30ms
	ScMaxBufferedPosts   int        // 服务端乱序缓冲上限，默认 30
	ScStreamUpServerSecs xhttpRange // stream-up 保活间隔，默认 20~80s

	// padding
	XPaddingBytes   xhttpRange // 默认 100~1000
	XPaddingObfs    bool       // 默认 false：走 Referer?x_padding
	XPaddingPlace   string
	XPaddingKey     string
	XPaddingHeader  string
	XPaddingMethod  string // repeat-x | tokenish

	// 元数据位置
	SessionPlacement string // 默认 path
	SessionKey       string
	SeqPlacement     string // 默认 path
	SeqKey           string

	NoGRPCHeader bool // 默认 false：上行带 Content-Type: application/grpc
	NoSSEHeader  bool // 默认 false：下行带 Content-Type: text/event-stream

	// 认证与通道标识（替代原 WebSocket subprotocol / query）
	Token     string
	ClientID  string
	ChannelID int
}

func defaultXHTTPConfig() *XHTTPConfig {
	return &XHTTPConfig{
		Mode:                 xhttpModePacketUp,
		Method:               http.MethodPost,
		ScMaxEachPostBytes:   xhttpRange{1000000, 1000000},
		ScMinPostsIntervalMs: xhttpRange{30, 30},
		ScMaxBufferedPosts:   30,
		ScStreamUpServerSecs: xhttpRange{20, 80},
		XPaddingBytes:        xhttpRange{100, 1000},
		XPaddingKey:          "x_padding",
		XPaddingHeader:       "X-Padding",
		XPaddingMethod:       "repeat-x",
		SessionPlacement:     xhttpPlacementPath,
		SeqPlacement:         xhttpPlacementPath,
	}
}

func (c *XHTTPConfig) normalize() {
	d := defaultXHTTPConfig()
	if c.Mode == "" {
		c.Mode = d.Mode
	}
	if c.Method == "" {
		c.Method = d.Method
	}
	if c.ScMaxEachPostBytes.To == 0 {
		c.ScMaxEachPostBytes = d.ScMaxEachPostBytes
	}
	if c.ScMaxBufferedPosts == 0 {
		c.ScMaxBufferedPosts = d.ScMaxBufferedPosts
	}
	if c.ScStreamUpServerSecs.To == 0 {
		c.ScStreamUpServerSecs = d.ScStreamUpServerSecs
	}
	if c.XPaddingBytes.To == 0 {
		c.XPaddingBytes = d.XPaddingBytes
	}
	if c.XPaddingKey == "" {
		c.XPaddingKey = d.XPaddingKey
	}
	if c.XPaddingHeader == "" {
		c.XPaddingHeader = d.XPaddingHeader
	}
	if c.XPaddingMethod == "" {
		c.XPaddingMethod = d.XPaddingMethod
	}
	if c.SessionPlacement == "" {
		c.SessionPlacement = xhttpPlacementPath
	}
	if c.SeqPlacement == "" {
		c.SeqPlacement = xhttpPlacementPath
	}
}

// 基础路径：路径部分补前导 '/'，若 session/seq 放在 path 则补尾随 '/'
func (c *XHTTPConfig) basePath() string {
	p := c.Path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if p == "" || !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if c.SessionPlacement == xhttpPlacementPath || c.SeqPlacement == xhttpPlacementPath {
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
	}
	return p
}

func (c *XHTTPConfig) baseQuery() string {
	if i := strings.IndexByte(c.Path, '?'); i >= 0 {
		return c.Path[i+1:]
	}
	return ""
}

func (c *XHTTPConfig) sessionKey() string {
	if c.SessionKey != "" {
		return c.SessionKey
	}
	if c.SessionPlacement == xhttpPlacementHeader {
		return "X-Session"
	}
	if c.SessionPlacement == xhttpPlacementCookie || c.SessionPlacement == xhttpPlacementQuery {
		return "x_session"
	}
	return ""
}

func (c *XHTTPConfig) seqKey() string {
	if c.SeqKey != "" {
		return c.SeqKey
	}
	if c.SeqPlacement == xhttpPlacementHeader {
		return "X-Seq"
	}
	if c.SeqPlacement == xhttpPlacementCookie || c.SeqPlacement == xhttpPlacementQuery {
		return "x_seq"
	}
	return ""
}

// ======================== padding ========================

const xhttpBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func xhttpGeneratePadding(method string, n int) string {
	if n <= 0 {
		return ""
	}
	if method != "tokenish" {
		return strings.Repeat("X", n)
	}
	out := make([]byte, n)
	for i := range out {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(xhttpBase62))))
		if err != nil {
			out[i] = 'X'
			continue
		}
		out[i] = xhttpBase62[v.Int64()]
	}
	return string(out)
}

// 默认模式（非 obfs）：padding 放在 Referer 的 x_padding 查询参数里
func (c *XHTTPConfig) paddingConfig(rawURL string) (placement string, key string, header string, length int) {
	length = c.XPaddingBytes.rand()
	if c.XPaddingObfs {
		return c.XPaddingPlace, c.XPaddingKey, c.XPaddingHeader, length
	}
	return "queryInHeader", "x_padding", "Referer", length
}

func xhttpApplyPadding(h http.Header, placement, key, header string, length int, method string, rawURL string) {
	val := xhttpGeneratePadding(method, length)
	switch placement {
	case xhttpPlacementHeader:
		h.Set(header, val)
	case "queryInHeader":
		h.Set(header, rawURL+"? "+key+"="+val)
	default:
		h.Set(header, rawURL+"? "+key+"="+val)
	}
}

func xhttpApplyPaddingQuery(u *url.URL, key string, length int, method string) {
	q := u.Query()
	q.Set(key, xhttpGeneratePadding(method, length))
	u.RawQuery = q.Encode()
}

func xhttpApplyPaddingCookie(h http.Header, key string, length int, method string) {
	httpCookieAdd(h, &http.Cookie{Name: key, Value: xhttpGeneratePadding(method, length), Path: "/"})
}

func httpCookieAdd(h http.Header, c *http.Cookie) {
	prev := h.Get("Cookie")
	if prev != "" {
		h.Set("Cookie", prev+"; "+c.Name+"="+c.String()[len(c.Name)+1:])
		return
	}
	h.Set("Cookie", c.String())
}

// 服务端：取出 padding 值（仅用于长度合法性校验）
func xhttpExtractPadding(r *http.Request, obfs bool, key, header string) (string, string) {
	if !obfs {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(strings.ReplaceAll(ref, "? ", "?")); err == nil {
				return u.Query().Get("x_padding"), "queryInHeader=Referer,key=x_padding"
			}
		}
		return r.URL.Query().Get("x_padding"), "query,key=x_padding"
	}
	if ck, err := r.Cookie(key); err == nil && ck.Value != "" {
		return ck.Value, "cookie,key=" + key
	}
	if v := r.Header.Get(header); v != "" {
		return v, "header=" + header
	}
	if v := r.URL.Query().Get(key); v != "" {
		return v, "query,key=" + key
	}
	return "", ""
}

// ======================== 元数据（sessionId / seq） ========================

func (c *XHTTPConfig) applyMeta(u *url.URL, h http.Header, sessionID, seqStr string) {
	if sessionID != "" {
		switch c.SessionPlacement {
		case xhttpPlacementPath:
			u.Path = xhttpAppendPath(u.Path, sessionID)
		case xhttpPlacementQuery:
			q := u.Query()
			q.Set(c.sessionKey(), sessionID)
			u.RawQuery = q.Encode()
		case xhttpPlacementHeader:
			h.Set(c.sessionKey(), sessionID)
		case xhttpPlacementCookie:
			httpCookieAdd(h, &http.Cookie{Name: c.sessionKey(), Value: sessionID, Path: "/"})
		}
	}
	if seqStr != "" {
		switch c.SeqPlacement {
		case xhttpPlacementPath:
			u.Path = xhttpAppendPath(u.Path, seqStr)
		case xhttpPlacementQuery:
			q := u.Query()
			q.Set(c.seqKey(), seqStr)
			u.RawQuery = q.Encode()
		case xhttpPlacementHeader:
			h.Set(c.seqKey(), seqStr)
		case xhttpPlacementCookie:
			httpCookieAdd(h, &http.Cookie{Name: c.seqKey(), Value: seqStr, Path: "/"})
		}
	}
}

func xhttpAppendPath(p, v string) string {
	if strings.HasSuffix(p, "/") {
		return p + v
	}
	return p + "/" + v
}

// basePath 为服务端已剥离的前缀路径
func (c *XHTTPConfig) extractMeta(r *http.Request, basePath string) (sessionID, seqStr string) {
	var sub []string
	pathPart := 0
	if c.SessionPlacement == xhttpPlacementPath || c.SeqPlacement == xhttpPlacementPath {
		rest := strings.TrimPrefix(r.URL.Path, basePath)
		sub = strings.Split(rest, "/")
	}
	switch c.SessionPlacement {
	case xhttpPlacementPath:
		if len(sub) > pathPart {
			sessionID = sub[pathPart]
			pathPart++
		}
	case xhttpPlacementQuery:
		sessionID = r.URL.Query().Get(c.sessionKey())
	case xhttpPlacementHeader:
		sessionID = r.Header.Get(c.sessionKey())
	case xhttpPlacementCookie:
		if ck, e := r.Cookie(c.sessionKey()); e == nil {
			sessionID = ck.Value
		}
	}
	switch c.SeqPlacement {
	case xhttpPlacementPath:
		if len(sub) > pathPart {
			seqStr = sub[pathPart]
		}
	case xhttpPlacementQuery:
		seqStr = r.URL.Query().Get(c.seqKey())
	case xhttpPlacementHeader:
		seqStr = r.Header.Get(c.seqKey())
	case xhttpPlacementCookie:
		if ck, e := r.Cookie(c.seqKey()); e == nil {
			seqStr = ck.Value
		}
	}
	return
}

// ======================== 客户端：xhttpNetConn ========================

type xhttpNetConn struct {
	cfg       *XHTTPConfig
	sessionID string
	baseURL   *url.URL
	client    *http.Client
	tlsCfg    *tls.Config

	readMu  sync.Mutex
	reader  io.ReadCloser

	writeMu   sync.Mutex
	seq       uint64
	lastWrite time.Time

	deadCh   chan struct{}
	deadMu   sync.Mutex
	deadErr  error
	deadOnce sync.Once

	ctx    context.Context
	cancel context.CancelFunc
}

// newXHTTPNetConn 建立一条 xhttp 逻辑连接（GET 下行 + POST 上行）
func newXHTTPNetConn(cfg *XHTTPConfig, client *http.Client, baseURL *url.URL, tlsCfg *tls.Config) (*xhttpNetConn, error) {
	cfg.normalize()
	sid := newXHTTPSessionID()
	ctx, cancel := context.WithCancel(context.Background())
	c := &xhttpNetConn{
		cfg:       cfg,
		sessionID: sid,
		baseURL:   baseURL,
		client:    client,
		tlsCfg:    tlsCfg,
		deadCh:    make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	if err := c.openDownlink(); err != nil {
		cancel()
		return nil, err
	}
	return c, nil
}

func newXHTTPSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (c *xhttpNetConn) buildURL(sessionID, seqStr string) (*url.URL, http.Header) {
	// stream-one：上下行在同一个请求里，不带 sessionId / seq
	if c.cfg.Mode == xhttpModeStreamOne {
		sessionID, seqStr = "", ""
	}
	u := *c.baseURL
	u.Path = c.cfg.basePath()
	u.RawQuery = c.cfg.baseQuery()
	h := make(http.Header)
	if c.cfg.Host != "" {
		h.Set("Host", c.cfg.Host)
	}
	h.Set("User-Agent", xhttpDefaultUA)
	h.Set("Accept", "*/*")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	if c.cfg.Token != "" {
		h.Set("X-Token", c.cfg.Token)
	}
	if c.cfg.ClientID != "" {
		h.Set("X-Client-Id", c.cfg.ClientID)
	}
	if c.cfg.ChannelID > 0 {
		h.Set("X-Channel-Id", strconv.Itoa(c.cfg.ChannelID))
	}

	pPlace, pKey, pHeader, pLen := c.cfg.paddingConfig(u.String())
	if pPlace == xhttpPlacementCookie {
		xhttpApplyPaddingCookie(h, pKey, pLen, c.cfg.XPaddingMethod)
	} else if pPlace == xhttpPlacementQuery {
		xhttpApplyPaddingQuery(&u, pKey, pLen, c.cfg.XPaddingMethod)
	} else {
		xhttpApplyPadding(h, pPlace, pKey, pHeader, pLen, c.cfg.XPaddingMethod, u.String())
	}
	c.cfg.applyMeta(&u, h, sessionID, seqStr)
	return &u, h
}

const xhttpDefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// openDownlink 发起一个长 GET，响应体作为读端
func (c *xhttpNetConn) openDownlink() error {
	u, h := c.buildURL(c.sessionID, "")
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	for k, vv := range h {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "text/event-stream")
	if !c.cfg.NoSSEHeader {
		req.Header.Set("X-Accel-Buffering", "no")
		req.Header.Set("Cache-Control", "no-store")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("xhttp 下行握手失败: HTTP %d", resp.StatusCode)
	}
	c.reader = resp.Body
	return nil
}

func (c *xhttpNetConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.reader == nil {
		if err := c.openDownlink(); err != nil {
			c.signalDead(err)
			return 0, err
		}
	}
	n, err := c.reader.Read(p)
	if err != nil {
		c.signalDead(err)
	}
	return n, err
}

func (c *xhttpNetConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	maxEach := c.cfg.ScMaxEachPostBytes.From
	if maxEach <= 0 {
		maxEach = 1000000
	}

	written := 0
	for written < len(p) {
		end := written + maxEach
		if end > len(p) {
			end = len(p)
		}
		chunk := p[written:end]

		if c.cfg.ScMinPostsIntervalMs.From > 0 {
			interval := time.Duration(c.cfg.ScMinPostsIntervalMs.rand()) * time.Millisecond
			if d := interval - time.Since(c.lastWrite); d > 0 {
				time.Sleep(d)
			}
		}
		c.lastWrite = time.Now()

		seq := ""
		if c.cfg.Mode == xhttpModePacketUp || c.cfg.Mode == xhttpModeAuto {
			seq = strconv.FormatUint(atomic.AddUint64(&c.seq, 1)-1, 10)
		}

		if err := c.postOne(chunk, seq); err != nil {
			c.signalDead(err)
			return written, err
		}
		written = end
	}
	return written, nil
}

// postOne 发送一个上行 POST（体为裸字节；元数据在 path/query/header/cookie）
func (c *xhttpNetConn) postOne(chunk []byte, seq string) error {
	u, h := c.buildURL(c.sessionID, seq)
	req, err := http.NewRequestWithContext(c.ctx, c.cfg.Method, u.String(), bytes.NewReader(chunk))
	if err != nil {
		return err
	}
	for k, vv := range h {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.ContentLength = int64(len(chunk))
	if !c.cfg.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	// 必须把响应体读完再关，否则连接无法复用（每个 POST 都会新建 TCP）
	_, _ = io.Copy(io.Discard, resp.Body)
	status := resp.StatusCode
	resp.Body.Close()
	if status != http.StatusOK {
		return fmt.Errorf("xhttp 上行返回 HTTP %d", status)
	}
	return nil
}

func (c *xhttpNetConn) Close() error {
	c.cancel()
	c.readMu.Lock()
	if c.reader != nil {
		_ = c.reader.Close()
		c.reader = nil
	}
	c.readMu.Unlock()
	c.signalDead(io.EOF)
	return nil
}

func (c *xhttpNetConn) signalDead(err error) {
	if err == nil {
		return
	}
	c.deadMu.Lock()
	if c.deadErr == nil {
		c.deadErr = err
	}
	c.deadMu.Unlock()
	c.deadOnce.Do(func() { close(c.deadCh) })
}

func (c *xhttpNetConn) Dead() <-chan struct{} { return c.deadCh }

func (c *xhttpNetConn) DeadErr() error {
	c.deadMu.Lock()
	defer c.deadMu.Unlock()
	return c.deadErr
}

func (c *xhttpNetConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *xhttpNetConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (c *xhttpNetConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *xhttpNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpNetConn) SetWriteDeadline(t time.Time) error { return nil }

// 供上层（smux）读取的“死链”接口
type deadliner interface {
	Dead() <-chan struct{}
	DeadErr() error
}

var _ deadliner = (*xhttpNetConn)(nil)

// ======================== 服务端：hub ========================

type xhttpPacket struct {
	seq     uint64
	payload []byte
}

type xhttpSession struct {
	id           string
	queue        chan xhttpPacket
	connected    chan struct{}
	connectedOne sync.Once
	closeOnce    sync.Once
	done         chan struct{}
}

func (s *xhttpSession) markConnected() {
	s.connectedOne.Do(func() { close(s.connected) })
}

func (s *xhttpSession) close() {
	s.closeOnce.Do(func() { close(s.done) })
}

type XHTTPServer struct {
	cfg *XHTTPConfig

	mu       sync.Mutex
	sessions map[string]*xhttpSession
}

func NewXHTTPServer(cfg *XHTTPConfig) *XHTTPServer {
	cfg.normalize()
	if cfg.Mode == xhttpModeAuto {
		cfg.Mode = xhttpModePacketUp
	}
	return &XHTTPServer{cfg: cfg, sessions: make(map[string]*xhttpSession)}
}

func (h *XHTTPServer) upsertSession(id string) *xhttpSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.sessions[id]; ok {
		return s
	}
	s := &xhttpSession{
		id:        id,
		queue:     make(chan xhttpPacket, h.cfg.ScMaxBufferedPosts),
		connected: make(chan struct{}),
		done:      make(chan struct{}),
	}
	h.sessions[id] = s
	// 30s 内没有 GET 接入则回收（与 Xray 的 reaper 一致）
	go func() {
		t := time.NewTimer(30 * time.Second)
		defer t.Stop()
		select {
		case <-t.C:
			select {
			case <-s.connected:
			default:
				h.mu.Lock()
				delete(h.sessions, id)
				h.mu.Unlock()
				s.close()
			}
		case <-s.connected:
		case <-s.done:
		}
	}()
	return s
}

func (h *XHTTPServer) dropSession(id string) {
	h.mu.Lock()
	if s, ok := h.sessions[id]; ok {
		delete(h.sessions, id)
		s.close()
	}
	h.mu.Unlock()
}

// ServeHTTP 处理 XHTTP 的 GET（下行）与 POST（上行）。
// 返回 true 表示该请求已被 xhttp 接管。
func (h *XHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request, ln *xhttpListener) bool {
	base := h.cfg.basePath()
	if !strings.HasPrefix(r.URL.Path, base) {
		return false
	}

	// CORS 预检
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusOK)
		return true
	}

	// padding 校验
	if pv, _ := xhttpExtractPadding(r, h.cfg.XPaddingObfs, h.cfg.XPaddingKey, h.cfg.XPaddingHeader); pv != "" {
		if len(pv) < h.cfg.XPaddingBytes.From || len(pv) > h.cfg.XPaddingBytes.To {
			http.Error(w, "bad padding", http.StatusBadRequest)
			return true
		}
	}

	sessionID, seqStr := h.cfg.extractMeta(r, base)

	// 下行：GET（且无 seq）
	if r.Method == http.MethodGet && seqStr == "" {
		if sessionID == "" {
			http.Error(w, "missing session", http.StatusBadRequest)
			return true
		}
		h.serveDownlink(w, r, sessionID, ln)
		return true
	}

	// 上行
	if sessionID == "" {
		http.Error(w, "missing session", http.StatusBadRequest)
		return true
	}
	h.serveUplink(w, r, sessionID, seqStr)
	return true
}

func (h *XHTTPServer) serveUplink(w http.ResponseWriter, r *http.Request, sessionID, seqStr string) {
	s := h.upsertSession(sessionID)

	limit := h.cfg.ScMaxEachPostBytes.To
	if limit <= 0 {
		limit = 1000000
	}
	if r.ContentLength > int64(limit) {
		http.Error(w, "post too large", http.StatusRequestEntityTooLarge)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(payload) > limit {
		http.Error(w, "post too large", http.StatusRequestEntityTooLarge)
		return
	}

	pkt := xhttpPacket{payload: payload}
	if seqStr != "" {
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			http.Error(w, "bad seq", http.StatusInternalServerError)
			return
		}
		pkt.seq = seq
	}

	select {
	case s.queue <- pkt:
	case <-s.done:
		http.Error(w, "session closed", http.StatusConflict)
		return
	default:
		http.Error(w, "queue full", http.StatusConflict)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// blocker 用于在 handler 返回后继续持有 ResponseWriter：
// Go 的 http.ResponseWriter 在 ServeHTTP 返回后不可再写，
// 这里把连接交给监听器管理，handler 阻塞直到流结束。
func (h *XHTTPServer) serveDownlink(w http.ResponseWriter, r *http.Request, sessionID string, ln *xhttpListener) {
	s := h.upsertSession(sessionID)
	s.markConnected()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	if !h.cfg.NoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	conn := &xhttpServerConn{
		w:         w,
		flusher:   flusher,
		queue:     s.queue,
		done:      make(chan struct{}),
		remote:    parseRemoteAddr(r.RemoteAddr),
		local:     &net.TCPAddr{},
		buf:       make([]byte, 0, 4096),
		pending:   make([]xhttpPacket, 0, 8),
		nextSeq:   0,
		noSeq:     h.cfg.Mode != xhttpModePacketUp,
		clientID:  r.Header.Get("X-Client-Id"),
		channelID: parseU64(r.Header.Get("X-Channel-Id")),
	}
	// 客户端断开 / 服务端关闭 都要结束这条下行
	go func() {
		select {
		case <-r.Context().Done():
		case <-conn.done:
		}
		conn.Close()
	}()

	// 说明：Xray 的 stream-up 保活 padding 由客户端按配置剥离；
	// 我们的下行直接被 smux 当作字节流读取，插入任何字节都会破坏帧，
	// 因此这里不发 padding，改用 X-Accel-Buffering:no + SSE 头来抑制 CDN 缓冲。

	ln.addConn(conn)
	<-conn.done
	h.dropSession(sessionID)
}

func parseRemoteAddr(s string) net.Addr {
	if a, err := net.ResolveTCPAddr("tcp", s); err == nil {
		return a
	}
	return &net.TCPAddr{}
}

func parseU64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// ======================== 服务端连接（net.Conn） ========================

type xhttpServerConn struct {
	w       http.ResponseWriter
	flusher http.Flusher
	queue   chan xhttpPacket

	// 由请求头带下来的通道标识
	clientID  string
	channelID uint64

	// 读侧状态用 readMu，写侧用 writeMu：上下行互不阻塞
	readMu  sync.Mutex
	buf     []byte
	pending []xhttpPacket
	nextSeq uint64
	noSeq   bool

	writeMu sync.Mutex

	done      chan struct{}
	closeOnce sync.Once
	err       error
	remote    net.Addr
	local     net.Addr
}

// Read 按 seq 顺序从上传队列取包（等价于 Xray 的 upload_queue min-heap）
func (c *xhttpServerConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	for len(c.buf) == 0 {
		if c.err != nil {
			err := c.err
			c.readMu.Unlock()
			return 0, err
		}
		// 先看缓存里有没有下一序号
		idx := -1
		for i := range c.pending {
			if c.noSeq || c.pending[i].seq == c.nextSeq {
				idx = i
				break
			}
		}
		if idx >= 0 {
			pkt := c.pending[idx]
			c.pending = append(c.pending[:idx], c.pending[idx+1:]...)
			c.buf = append(c.buf, pkt.payload...)
			if !c.noSeq {
				c.nextSeq++
			}
			continue
		}

		// 缓存的都是“未来”的包，等待缺号
		c.readMu.Unlock()
		select {
		case pkt, ok := <-c.queue:
			c.readMu.Lock()
			if !ok {
				c.err = io.EOF
				continue
			}
			c.pending = append(c.pending, pkt)
		case <-c.done:
			c.readMu.Lock()
			c.err = io.EOF
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	c.readMu.Unlock()
	return n, nil
}

func (c *xhttpServerConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return n, nil
}

func (c *xhttpServerConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *xhttpServerConn) LocalAddr() net.Addr  { return c.local }
func (c *xhttpServerConn) RemoteAddr() net.Addr { return c.remote }
func (c *xhttpServerConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *xhttpServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpServerConn) SetWriteDeadline(t time.Time) error { return nil }

// ======================== 监听器 ========================

type xhttpListener struct {
	cfg    *XHTTPConfig
	server *XHTTPServer
	connCh chan net.Conn
	closeC chan struct{}
	once   sync.Once

	// onConn 在下行 GET 建立后回调（用于把连接登记到通道表）
	onConn func(net.Conn)
}

func NewXHTTPListener(cfg *XHTTPConfig) *xhttpListener {
	cfg.normalize()
	return &xhttpListener{
		cfg:    cfg,
		server: NewXHTTPServer(cfg),
		connCh: make(chan net.Conn, 64),
		closeC: make(chan struct{}),
	}
}

// SetConnCallback 设置新连接回调；必须在开始服务前调用
func (l *xhttpListener) SetConnCallback(fn func(net.Conn)) { l.onConn = fn }

func (l *xhttpListener) addConn(c net.Conn) {
	select {
	case l.connCh <- c:
	case <-l.closeC:
		_ = c.Close()
		return
	}
	if l.onConn != nil {
		l.onConn(c)
	}
}

func (l *xhttpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connCh:
		return c, nil
	case <-l.closeC:
		return nil, io.EOF
	}
}

func (l *xhttpListener) Close() error {
	l.once.Do(func() { close(l.closeC) })
	return nil
}

// ServeHTTP 供 http.Server 挂载
func (l *xhttpListener) ServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	return l.server.ServeHTTP(w, r, l)
}

// ======================== 客户端构造 ========================

// NewXHTTPClient 构造一个 HTTP 客户端 + 基础 URL + TLS 配置
func NewXHTTPClient(addr string, cfg *XHTTPConfig, tlsCfg *tls.Config, ipForDial string) (*http.Client, *url.URL, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "xhttp" && u.Scheme != "xhttps" && u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, nil, fmt.Errorf("xhttp 仅支持 xhttp:// xhttps:// (当前: %s)", u.Scheme)
	}
	useTLS := u.Scheme == "xhttps" || u.Scheme == "wss"

	base := &url.URL{
		Scheme: "http",
		Host:   u.Host,
	}
	if useTLS {
		base.Scheme = "https"
	}
	if cfg.Path == "" {
		cfg.Path = u.Path
	}
	if cfg.Host == "" {
		cfg.Host = u.Host
	}

	dialer := &net.Dialer{Timeout: cfg2DialTimeout()}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			target := address
			if ipForDial != "" {
				_, port, _ := net.SplitHostPort(address)
				if h, p, e := net.SplitHostPort(ipForDial); e == nil {
					target = net.JoinHostPort(h, p)
				} else {
					target = net.JoinHostPort(ipForDial, port)
				}
			}
			return dialer.DialContext(ctx, network, target)
		},
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		// 关键：让 GET 的响应体能边到边读，不被整块缓冲
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
	}
	client := &http.Client{
		Transport: tr,
		// 下行是无限流，不能设整体超时
		Timeout: 0,
	}
	return client, base, nil
}

func cfg2DialTimeout() time.Duration {
	if cfg.DialTimeout > 0 {
		return cfg.DialTimeout
	}
	return 3 * time.Second
}

// dialXHTTP 为上层提供一个与 dialWebSocketWithECH 等价的入口
func dialXHTTP(addr string, cfg *XHTTPConfig, tlsCfg *tls.Config, ipForDial string) (*xhttpNetConn, error) {
	client, base, err := NewXHTTPClient(addr, cfg, tlsCfg, ipForDial)
	if err != nil {
		return nil, err
	}
	return newXHTTPNetConn(cfg, client, base, tlsCfg)
}
