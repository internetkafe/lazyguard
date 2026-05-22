package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
)

const (
	ShardCount  = 32
	MaxRetries  = 5
	MetricsAddr = ":9100"
)

type ip4Attr uint32
type ip6Attr [16]byte

type BanInfo struct {
	IPStr     string
	UnbanTime time.Time
	IsV4      bool
	V4Key     ip4Attr
	V6Key     ip6Attr
	RetryCount int
	Unbanning bool
}

type CounterShard struct {
	mu        sync.Mutex
	ip4Counts map[ip4Attr]int
	ip6Counts map[ip6Attr]int
}

type AntiDDoS struct {
	mu            sync.RWMutex
	bannedIPv4    map[ip4Attr]time.Time
	bannedIPv6    map[ip6Attr]time.Time
	bannedDetails map[string]BanInfo
	retryQueue    map[string]BanInfo

	shards [ShardCount]*CounterShard

	whitelistV4   map[ip4Attr]bool
	whitelistV6   map[ip6Attr]bool
	whitelistNets []*net.IPNet

	interfaceName string
	targetPort    uint16
	packetLimit   int
	connLimit     int
	maxBans       int
	checkInterval time.Duration
	banDuration   time.Duration
	hasIPv6       bool

	// Метрики
	evictionCount    uint64
	evictionErrors   uint64
	packetDropEst    uint64
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("[INFO] .env не найден, используются значения по умолчанию")
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		log.Fatalf("[FATAL] iptables не найден")
	}
	hasIPv6 := true
	if _, err := exec.LookPath("ip6tables"); err != nil {
		log.Println("[WARN] ip6tables не найден, IPv6 отключена")
		hasIPv6 = false
	}

	app := &AntiDDoS{
		bannedIPv4:    make(map[ip4Attr]time.Time, 1024),
		bannedIPv6:    make(map[ip6Attr]time.Time, 256),
		bannedDetails: make(map[string]BanInfo, 1280),
		retryQueue:    make(map[string]BanInfo),
		whitelistV4:   make(map[ip4Attr]bool),
		whitelistV6:   make(map[ip6Attr]bool),
		interfaceName: getEnv("INTERFACE", "eth0"),
		targetPort:    uint16(getEnvInt("TARGET_PORT", 443)),
		packetLimit:   getEnvInt("PACKET_LIMIT", 250),
		connLimit:     getEnvInt("CONN_LIMIT", 60),
		maxBans:       getEnvInt("MAX_BANS_LIMIT", 5000),
		checkInterval: time.Duration(getEnvInt("CHECK_INTERVAL_SEC", 2)) * time.Second,
		banDuration:   time.Duration(getEnvInt("BAN_TIME_SEC", 3600)) * time.Second,
		hasIPv6:       hasIPv6,
	}

	for i := 0; i < ShardCount; i++ {
		app.shards[i] = &CounterShard{
			ip4Counts: make(map[ip4Attr]int, 512),
			ip6Counts: make(map[ip6Attr]int, 128),
		}
	}

	app.initWhitelist(strings.Split(getEnv("WHITELIST", "127.0.0.1,::1"), ","))
	app.flushIptablesRaw() // Очистка RAW‑цепи при старте

	fmt.Println("==================================================")
	fmt.Printf("  LazyGuard Unified v8.0 – %s:%d\n", app.interfaceName, app.targetPort)
	fmt.Println("==================================================")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// HTTP‑метрики
	go app.startMetricsServer()

	// Захват пакетов
	handle, err := pcap.OpenLive(app.interfaceName, 64, true, 1*time.Second)
	if err != nil {
		cancel()
		log.Fatalf("[FATAL] pcap: %v", err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(fmt.Sprintf("dst port %d", app.targetPort)); err != nil {
		cancel()
		log.Fatalf("[FATAL] BPF: %v", err)
	}

	wg.Add(4)
	go app.packetWorker(ctx, &wg, handle)
	go app.socketScanner(ctx, &wg)
	go app.analyzerLoop(ctx, &wg)
	go app.unbanLoop(ctx, &wg)
	go app.retryCleanupLoop(ctx, &wg)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n[*] Завершение работы...")
	cancel()
	wg.Wait()
	app.cleanupAllBans()
	fmt.Println("[*] LazyGuard остановлен.")
}

// ========== Обработка пакетов (шардированные счётчики) ==========
func (a *AntiDDoS) packetWorker(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle) {
	defer wg.Done()
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6)
	decoded := make([]gopacket.LayerType, 0, 4)

	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if err.Error() == "Timeout Expired" {
				continue
			}
			log.Printf("[PCAP] Ошибка: %v", err)
			return
		}

		decoded = decoded[:0]
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			continue
		}

		var isV4 bool
		var v4Key ip4Attr
		var v6Key ip6Attr
		var srcIP net.IP

		for _, lt := range decoded {
			if lt == layers.LayerTypeIPv4 {
				if len(ip4.SrcIP) >= 4 {
					v4Key = ip4Attr(ip4.SrcIP[0])<<24 | ip4Attr(ip4.SrcIP[1])<<16 | ip4Attr(ip4.SrcIP[2])<<8 | ip4Attr(ip4.SrcIP[3])
					srcIP = ip4.SrcIP
					isV4 = true
				}
				break
			}
			if lt == layers.LayerTypeIPv6 && a.hasIPv6 {
				if len(ip6.SrcIP) == 16 {
					copy(v6Key[:], ip6.SrcIP)
					srcIP = ip6.SrcIP
					isV4 = false
				}
				break
			}
		}
		if srcIP == nil {
			continue
		}

		// Проверка белого списка и уже забаненных (без блокировки записи)
		a.mu.RLock()
		var skip bool
		if isV4 {
			if a.whitelistV4[v4Key] || a.isInCIDR(srcIP) || a.hasBanV4(v4Key) {
				skip = true
			}
		} else {
			if a.whitelistV6[v6Key] || a.isInCIDR(srcIP) || a.hasBanV6(v6Key) {
				skip = true
			}
		}
		a.mu.RUnlock()
		if skip {
			continue
		}

		// Инкремент в шарде
		if isV4 {
			shard := a.shards[v4Key%ShardCount]
			shard.mu.Lock()
			shard.ip4Counts[v4Key]++
			shard.mu.Unlock()
		} else {
			idx := hashIPv6(v6Key) % ShardCount
			shard := a.shards[idx]
			shard.mu.Lock()
			shard.ip6Counts[v6Key]++
			shard.mu.Unlock()
		}
	}
}

// ========== Сканер сокетов (число соединений) ==========
func (a *AntiDDoS) socketScanner(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conns := make(map[string]int)
			a.parseProcFile("/proc/net/tcp", conns, false)
			a.parseProcFile("/proc/net/tcp6", conns, true)

			for ip, cnt := range conns {
				if cnt > a.connLimit {
					isV4 := !strings.Contains(ip, ":")
					a.banIP(BanInfo{
						IPStr:     ip,
						IsV4:      isV4,
						UnbanTime: time.Now().Add(a.banDuration),
					})
				}
			}
		}
	}
}

func (a *AntiDDoS) parseProcFile(path string, dst map[string]int, isV6 bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "01" { // ESTABLISHED
			continue
		}
		// Парсим локальный порт
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}
		port64, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil || uint16(port64) != a.targetPort {
			continue
		}
		// IP источника
		addrParts := strings.Split(fields[2], ":")
		if len(addrParts) != 2 {
			continue
		}
		var ipStr string
		if isV6 {
			ipStr = formatIPv6(addrParts[0])
		} else {
			ipStr = formatIPv4(addrParts[0])
		}
		if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" {
			continue
		}
		dst[ipStr]++
	}
}

func formatIPv4(hexStr string) string {
	b, _ := hex.DecodeString(hexStr)
	if len(b) != 4 {
		return ""
	}
	return net.IPv4(b[3], b[2], b[1], b[0]).String()
}

func formatIPv6(hexStr string) string {
	b, _ := hex.DecodeString(hexStr)
	if len(b) != 16 {
		return ""
	}
	// Переворачиваем группы по 4 байта (little‑endian to big‑endian)
	for i := 0; i < 16; i += 4 {
		b[i], b[i+3] = b[i+3], b[i]
		b[i+1], b[i+2] = b[i+2], b[i+1]
	}
	return net.IP(b).String()
}

// ========== Анализатор (флуд пакетов) ==========
func (a *AntiDDoS) analyzerLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.checkInterval)
	defer ticker.Stop()

	toBan := make([]BanInfo, 0, 128)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			toBan = toBan[:0]
			now := time.Now()
			for i := 0; i < ShardCount; i++ {
				shard := a.shards[i]
				shard.mu.Lock()
				for k, v := range shard.ip4Counts {
					if v > a.packetLimit {
						toBan = append(toBan, BanInfo{
							IPStr:     byteToIPv4Str(uint32(k)),
							IsV4:      true,
							V4Key:     k,
							UnbanTime: now.Add(a.banDuration),
						})
					}
				}
				for k, v := range shard.ip6Counts {
					if v > a.packetLimit {
						toBan = append(toBan, BanInfo{
							IPStr:     net.IP(k[:]).String(),
							IsV4:      false,
							V6Key:     k,
							UnbanTime: now.Add(a.banDuration),
						})
					}
				}
				// Очистка
				for k := range shard.ip4Counts {
					delete(shard.ip4Counts, k)
				}
				for k := range shard.ip6Counts {
					delete(shard.ip6Counts, k)
				}
				shard.mu.Unlock()
			}
			for _, info := range toBan {
				a.banIP(info)
			}
		}
	}
}

// ========== Агрессивный бан (RAW + conntrack + tcpkill) ==========
func (a *AntiDDoS) banIP(info BanInfo) {
	a.mu.Lock()
	// Дубликат?
	if _, exists := a.bannedDetails[info.IPStr]; exists {
		a.mu.Unlock()
		return
	}

	// Проверка лимита и вытеснение старого
	if len(a.bannedDetails) >= a.maxBans {
		var oldest BanInfo
		found := false
		for _, bi := range a.bannedDetails {
			if !bi.Unbanning && (oldest.IPStr == "" || bi.UnbanTime.Before(oldest.UnbanTime)) {
				oldest = bi
				found = true
			}
		}
		if found {
			// Удаляем из карт, чтобы не мешать вытеснению
			if oldest.IsV4 {
				delete(a.bannedIPv4, oldest.V4Key)
			} else {
				delete(a.bannedIPv6, oldest.V6Key)
			}
			delete(a.bannedDetails, oldest.IPStr)
			a.mu.Unlock()

			// Фоновое удаление правила (RAW)
			go a.evictOldest(oldest)
			a.mu.Lock() // снова захватываем для продолжения
		}
	}

	// Уже успели забанить за время вытеснения?
	if _, exists := a.bannedDetails[info.IPStr]; exists {
		a.mu.Unlock()
		return
	}

	cmdName := "iptables"
	if !info.IsV4 {
		cmdName = "ip6tables"
	}

	// 1. RAW drop
	if err := exec.Command(cmdName, "-t", "raw", "-I", "PREROUTING", "-s", info.IPStr, "-j", "DROP").Run(); err != nil {
		log.Printf("[BAN ERROR] iptables: %v", err)
		a.mu.Unlock()
		return
	}

	// 2. Сброс conntrack (убираем существующие записи)
	port := fmt.Sprintf("%d", a.targetPort)
	exec.Command("conntrack", "-D", "-s", info.IPStr, "--dport", port).Run()
	exec.Command("conntrack", "-D", "-s", info.IPStr).Run()

	// 3. Агрессивный разрыв соединений через tcpkill
	go func(ip string, iface string) {
		log.Printf("[KILL] Разрыв TCP-соединений от %s", ip)
		exec.Command("timeout", "5s", "tcpkill", "-i", iface, "host", ip).Run()
	}(info.IPStr, a.interfaceName)

	// Фиксация в структурах
	info.Unbanning = false
	a.bannedDetails[info.IPStr] = info
	if info.IsV4 {
		a.bannedIPv4[info.V4Key] = info.UnbanTime
	} else {
		a.bannedIPv6[info.V6Key] = info.UnbanTime
	}
	delete(a.retryQueue, info.IPStr)
	a.mu.Unlock()

	log.Printf("[BANNED] %s заблокирован на %v", info.IPStr, a.banDuration)
}

func (a *AntiDDoS) evictOldest(old BanInfo) {
	cmdName := "iptables"
	if !old.IsV4 {
		cmdName = "ip6tables"
	}
	if err := exec.Command(cmdName, "-t", "raw", "-D", "PREROUTING", "-s", old.IPStr, "-j", "DROP").Run(); err != nil {
		atomic.AddUint64(&a.evictionErrors, 1)
		log.Printf("[EVICT ERR] Не удалось снять правило для %s: %v", old.IPStr, err)
		// Отправляем в карантин
		a.mu.Lock()
		if _, still := a.bannedDetails[old.IPStr]; !still {
			a.retryQueue[old.IPStr] = old
		}
		a.mu.Unlock()
	} else {
		atomic.AddUint64(&a.evictionCount, 1)
	}
}

// ========== Разбан по таймеру ==========
func (a *AntiDDoS) unbanLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var expired []BanInfo
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expired = expired[:0]
			now := time.Now()
			a.mu.RLock()
			for _, bi := range a.bannedDetails {
				if !bi.Unbanning && now.After(bi.UnbanTime) {
					expired = append(expired, bi)
				}
			}
			a.mu.RUnlock()
			for _, bi := range expired {
				a.unbanIP(bi.IPStr, bi.UnbanTime)
			}
		}
	}
}

func (a *AntiDDoS) unbanIP(ip string, targetUnban time.Time) {
	a.mu.Lock()
	cur, ok := a.bannedDetails[ip]
	if !ok || cur.Unbanning || !cur.UnbanTime.Equal(targetUnban) {
		a.mu.Unlock()
		return
	}
	cur.Unbanning = true
	a.bannedDetails[ip] = cur
	a.mu.Unlock()

	cmdName := "iptables"
	if !cur.IsV4 {
		cmdName = "ip6tables"
	}
	err := exec.Command(cmdName, "-t", "raw", "-D", "PREROUTING", "-s", ip, "-j", "DROP").Run()

	a.mu.Lock()
	// Повторная проверка (могли перебанить)
	if current, still := a.bannedDetails[ip]; still && current.UnbanTime.Equal(targetUnban) {
		if err != nil {
			log.Printf("[UNBAN ERR] %s: %v, в карантин", ip, err)
			a.retryQueue[ip] = current
		}
		if current.IsV4 {
			delete(a.bannedIPv4, current.V4Key)
		} else {
			delete(a.bannedIPv6, current.V6Key)
		}
		delete(a.bannedDetails, ip)
	}
	a.mu.Unlock()
	if err == nil {
		log.Printf("[UNBANNED] %s", ip)
	}
}

// ========== Карантин (повторные попытки удалить зомби‑правила) ==========
func (a *AntiDDoS) retryCleanupLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var local []BanInfo
			a.mu.RLock()
			for _, bi := range a.retryQueue {
				local = append(local, bi)
			}
			a.mu.RUnlock()

			var dead []string
			for _, bi := range local {
				cmdName := "iptables"
				if !bi.IsV4 {
					cmdName = "ip6tables"
				}
				if err := exec.Command(cmdName, "-t", "raw", "-D", "PREROUTING", "-s", bi.IPStr, "-j", "DROP").Run(); err == nil {
					a.mu.Lock()
					delete(a.retryQueue, bi.IPStr)
					a.mu.Unlock()
					log.Printf("[CLEANUP] Зомби %s удалён", bi.IPStr)
				} else {
					bi.RetryCount++
					if bi.RetryCount >= MaxRetries {
						dead = append(dead, bi.IPStr)
						a.mu.Lock()
						delete(a.retryQueue, bi.IPStr)
						a.mu.Unlock()
					} else {
						a.mu.Lock()
						a.retryQueue[bi.IPStr] = bi
						a.mu.Unlock()
					}
				}
			}
			if len(dead) > 0 {
				log.Printf("[WARN] %d IP не удалены из iptables после %d попыток: %v",
					len(dead), MaxRetries, dead)
			}
		}
	}
}

// ========== Вспомогательные методы ==========
func (a *AntiDDoS) hasBanV4(k ip4Attr) bool { _, ok := a.bannedIPv4[k]; return ok }
func (a *AntiDDoS) hasBanV6(k ip6Attr) bool { _, ok := a.bannedIPv6[k]; return ok }

func (a *AntiDDoS) isInCIDR(ip net.IP) bool {
	for _, n := range a.whitelistNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *AntiDDoS) initWhitelist(items []string) {
	for _, raw := range items {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			_, ipNet, err := net.ParseCIDR(raw)
			if err == nil {
				a.whitelistNets = append(a.whitelistNets, ipNet)
				log.Printf("[WHITELIST] CIDR %s", ipNet)
			}
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			a.whitelistV4[ip4Attr(v4[0])<<24|ip4Attr(v4[1])<<16|ip4Attr(v4[2])<<8|ip4Attr(v4[3])] = true
			log.Printf("[WHITELIST] IPv4 %s", ip)
		} else if a.hasIPv6 {
			var k ip6Attr
			copy(k[:], ip.To16())
			a.whitelistV6[k] = true
			log.Printf("[WHITELIST] IPv6 %s", ip)
		}
	}
}

func (a *AntiDDoS) flushIptablesRaw() {
	exec.Command("iptables", "-t", "raw", "-F", "PREROUTING").Run()
	if a.hasIPv6 {
		exec.Command("ip6tables", "-t", "raw", "-F", "PREROUTING").Run()
	}
}

func (a *AntiDDoS) cleanupAllBans() {
	var active, zombie []BanInfo
	a.mu.RLock()
	for _, bi := range a.bannedDetails {
		active = append(active, bi)
	}
	for _, bi := range a.retryQueue {
		zombie = append(zombie, bi)
	}
	a.mu.RUnlock()

	for _, bi := range active {
		cmd := "iptables"
		if !bi.IsV4 {
			cmd = "ip6tables"
		}
		exec.Command(cmd, "-t", "raw", "-D", "PREROUTING", "-s", bi.IPStr, "-j", "DROP").Run()
	}
	for _, bi := range zombie {
		cmd := "iptables"
		if !bi.IsV4 {
			cmd = "ip6tables"
		}
		exec.Command(cmd, "-t", "raw", "-D", "PREROUTING", "-s", bi.IPStr, "-j", "DROP").Run()
	}
	log.Printf("[CLEANUP] Все правила RAW удалены")
}

func (a *AntiDDoS) startMetricsServer() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		a.mu.RLock()
		active := len(a.bannedDetails)
		zombie := len(a.retryQueue)
		a.mu.RUnlock()

		fmt.Fprintf(w, "# HELP lazyguard_active_bans Active bans\n")
		fmt.Fprintf(w, "# TYPE lazyguard_active_bans gauge\n")
		fmt.Fprintf(w, "lazyguard_active_bans %d\n", active)
		fmt.Fprintf(w, "# HELP lazyguard_zombie_quarantine Zombie rules in quarantine\n")
		fmt.Fprintf(w, "# TYPE lazyguard_zombie_quarantine gauge\n")
		fmt.Fprintf(w, "lazyguard_zombie_quarantine %d\n", zombie)
		fmt.Fprintf(w, "# HELP lazyguard_evictions_total Successful evictions\n")
		fmt.Fprintf(w, "# TYPE lazyguard_evictions_total counter\n")
		fmt.Fprintf(w, "lazyguard_evictions_total %d\n", atomic.LoadUint64(&a.evictionCount))
		fmt.Fprintf(w, "# HELP lazyguard_eviction_errors_total Failed evictions\n")
		fmt.Fprintf(w, "# TYPE lazyguard_eviction_errors_total counter\n")
		fmt.Fprintf(w, "lazyguard_eviction_errors_total %d\n", atomic.LoadUint64(&a.evictionErrors))
	})
	addr := "127.0.0.1" + MetricsAddr
	log.Printf("[METRICS] Запущен на %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("[METRICS] Ошибка: %v", err)
	}
}

func hashIPv6(k ip6Attr) uint32 {
	h := fnv.New32a()
	h.Write(k[:])
	return h.Sum32()
}

func byteToIPv4Str(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
