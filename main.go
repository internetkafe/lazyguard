package main

import (
	"context"
	"encoding/binary"
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
	IPStr      string
	UnbanTime  time.Time
	IsV4       bool
	V4Key      ip4Attr
	V6Key      ip6Attr
	RetryCount int
	Unbanning  bool 
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
	targetPort    string
	packetLimit   int
	maxBans       int
	checkInterval time.Duration
	banDuration   time.Duration
	hasIPv6       bool

	// Мониторинг v7.3
	evictionCount uint64 
	evictionErrors uint64
	packetDropEst uint64 
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("[INFO] .env файл не найден, используются дефолтные настройки")
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		log.Fatalf("[FATAL] Бинарник 'iptables' не найден в PATH.")
	}

	hasIPv6 := true
	if _, err := exec.LookPath("ip6tables"); err != nil {
		log.Println("[WARN] 'ip6tables' не найден. Поддержка IPv6 отключена.")
		hasIPv6 = false
	}

	anti := &AntiDDoS{
		bannedIPv4:    make(map[ip4Attr]time.Time, 1024),
		bannedIPv6:    make(map[ip6Attr]time.Time, 256),
		bannedDetails: make(map[string]BanInfo, 1280),
		retryQueue:    make(map[string]BanInfo),
		whitelistV4:   make(map[ip4Attr]bool),
		whitelistV6:   make(map[ip6Attr]bool),
		interfaceName: getEnv("INTERFACE", "eth0"),
		targetPort:    getEnv("TARGET_PORT", "443"),
		packetLimit:   getEnvInt("PACKET_LIMIT", 250),
		maxBans:       getEnvInt("MAX_BANS_LIMIT", 5000),
		checkInterval: time.Duration(getEnvInt("CHECK_INTERVAL_SEC", 2)) * time.Second,
		banDuration:   time.Duration(getEnvInt("BAN_TIME_SEC", 3600)) * time.Second,
		hasIPv6:       hasIPv6,
	}

	for i := 0; i < ShardCount; i++ {
		anti.shards[i] = &CounterShard{
			ip4Counts: make(map[ip4Attr]int, 512),
			ip6Counts: make(map[ip6Attr]int, 128),
		}
	}

	anti.initWhitelist(strings.Split(getEnv("WHITELIST", "127.0.0.1,::1"), ","))

	fmt.Println("==================================================")
	fmt.Println("     LazyGuard v7.3 - GA PRODUCTION               ")
	fmt.Println("==================================================")
	fmt.Printf("[*] Интерфейс: %s | Порт: %s\n", anti.interfaceName, anti.targetPort)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	go anti.startMetricsServer()

	handle, err := pcap.OpenLive(anti.interfaceName, 64, true, 1*time.Second)
	if err != nil {
		cancel()
		log.Fatalf("[FATAL] Ошибка открытия pcap: %v", err)
	}

	if err := handle.SetBPFFilter(fmt.Sprintf("dst port %s", anti.targetPort)); err != nil {
		handle.Close()
		cancel()
		log.Fatalf("[FATAL] Ошибка BPF: %v", err)
	}

	wg.Add(4)
	go anti.analyzerLoop(ctx, &wg)
	go anti.unbanLoop(ctx, &wg)
	go anti.retryCleanupLoop(ctx, &wg)

	pcapErrorChan := make(chan error, 1)
	go func() {
		defer wg.Done()
		var eth layers.Ethernet
		var ip4 layers.IPv4
		var ip6 layers.IPv6
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6)
		decodedLayers := make([]gopacket.LayerType, 0, 4)

		for {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// Безопасная обработка таймаутов pcap без использования сырых констант
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if err.Error() == "Timeout Expired" {
					continue
				}
				pcapErrorChan <- err
				return
			}

			decodedLayers = decodedLayers[:0]
			if err := parser.DecodeLayers(data, &decodedLayers); err != nil {
				continue
			}

			var isV4 bool
			var v4Key ip4Attr
			var v6Key ip6Attr
			var hasIP bool
			var runtimeIP net.IP

			for _, layerType := range decodedLayers {
				if layerType == layers.LayerTypeIPv4 {
					if len(ip4.SrcIP) >= 4 {
						v4Key = ip4Attr(binary.BigEndian.Uint32(ip4.SrcIP))
						runtimeIP = ip4.SrcIP
						isV4 = true
						hasIP = true
					}
					break
				} else if layerType == layers.LayerTypeIPv6 && anti.hasIPv6 {
					if len(ip6.SrcIP) == 16 {
						copy(v6Key[:], ip6.SrcIP)
						runtimeIP = ip6.SrcIP
						isV4 = false
						hasIP = true
					}
					break
				}
			}

			if !hasIP {
				continue
			}

			anti.mu.RLock()
			var skipped bool
			var isBanned bool

			if isV4 {
				if anti.whitelistV4[v4Key] || anti.isInCIDR(runtimeIP) {
					skipped = true
				} else if anti.hasBanV4(v4Key) {
					skipped = true
					isBanned = true
				}
			} else {
				if anti.whitelistV6[v6Key] || anti.isInCIDR(runtimeIP) {
					skipped = true
				} else if anti.hasBanV6(v6Key) {
					skipped = true
					isBanned = true
				}
			}
			anti.mu.RUnlock()

			if skipped {
				if isBanned {
					atomic.AddUint64(&anti.packetDropEst, 1)
				}
				continue
			}

			if isV4 {
				shard := anti.shards[v4Key%ShardCount]
				shard.mu.Lock()
				shard.ip4Counts[v4Key]++
				shard.mu.Unlock()
			} else {
				shardIdx := hashIPv6(v6Key) % ShardCount
				shard := anti.shards[shardIdx]
				shard.mu.Lock()
				shard.ip6Counts[v6Key]++
				shard.mu.Unlock()
			}
		}
	}()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stopChan:
		fmt.Printf("\n[*] Получен сигнал %v. Корректно завершаем работу...\n", sig)
	case pcapErr := <-pcapErrorChan:
		log.Printf("[FATAL] Критическая ошибка сетевого интерфейса: %v\n", pcapErr)
	}

	cancel()
	handle.Close()
	wg.Wait()

	anti.cleanupAllBans()
	fmt.Println("[*] LazyGuard успешно остановлен.")
}

func (a *AntiDDoS) hasBanV4(key ip4Attr) bool { _, b := a.bannedIPv4[key]; return b }
func (a *AntiDDoS) hasBanV6(key ip6Attr) bool { _, b := a.bannedIPv6[key]; return b }

func (a *AntiDDoS) isInCIDR(ip net.IP) bool {
	for _, netRange := range a.whitelistNets {
		if netRange.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *AntiDDoS) analyzerLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.checkInterval)
	defer ticker.Stop()

	var targetsToBan []BanInfo

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			targetsToBan = targetsToBan[:0]
			now := time.Now()

			for i := 0; i < ShardCount; i++ {
				shard := a.shards[i]
				shard.mu.Lock()
				for ipRaw, count := range shard.ip4Counts {
					if count > a.packetLimit {
						// Явное приведение типов ip4Attr -> uint32 для компилятора
						targetsToBan = append(targetsToBan, BanInfo{
							IPStr: byteToIPv4Str(uint32(ipRaw)), IsV4: true, V4Key: ipRaw, UnbanTime: now.Add(a.banDuration),
						})
					}
				}
				for ipRaw, count := range shard.ip6Counts {
					if count > a.packetLimit {
						targetsToBan = append(targetsToBan, BanInfo{
							IPStr: net.IP(ipRaw[:]).String(), IsV4: false, V6Key: ipRaw, UnbanTime: now.Add(a.banDuration),
						})
					}
				}
				for k := range shard.ip4Counts { delete(shard.ip4Counts, k) }
				for k := range shard.ip6Counts { delete(shard.ip6Counts, k) }
				shard.mu.Unlock()
			}

			for _, target := range targetsToBan {
				a.banIP(target)
			}
		}
	}
}

func (a *AntiDDoS) banIP(info BanInfo) {
	a.mu.Lock()
	if info.IsV4 {
		if _, already := a.bannedIPv4[info.V4Key]; already {
			a.mu.Unlock()
			return
		}
	} else {
		if _, already := a.bannedIPv6[info.V6Key]; already {
			a.mu.Unlock()
			return
		}
	}

	if len(a.bannedDetails) >= a.maxBans {
		var oldestIP string
		var oldestTime time.Time
		found := false

		for ip, detail := range a.bannedDetails {
			if !detail.Unbanning && (oldestIP == "" || detail.UnbanTime.Before(oldestTime)) {
				oldestIP = ip
				oldestTime = detail.UnbanTime
				found = true
			}
		}

		if found {
			evictedInfo := a.bannedDetails[oldestIP]
			if evictedInfo.IsV4 {
				delete(a.bannedIPv4, evictedInfo.V4Key)
			} else {
				delete(a.bannedIPv6, evictedInfo.V6Key)
			}
			delete(a.bannedDetails, oldestIP)

			go func(bi BanInfo, targetUnban time.Time) {
				cmd := "iptables"
				if !bi.IsV4 { cmd = "ip6tables" }
				
				a.mu.RLock()
				current, active := a.bannedDetails[bi.IPStr]
				a.mu.RUnlock()
				
				if active && !current.UnbanTime.Equal(targetUnban) {
					return 
				}

				if err := exec.Command(cmd, "-D", "INPUT", "-s", bi.IPStr, "-j", "DROP").Run(); err != nil {
					atomic.AddUint64(&a.evictionErrors, 1)
					log.Printf("[WARN] Сбой вытеснения %s. Отправлен в карантин.\n", bi.IPStr)
					a.mu.Lock()
					if current, active := a.bannedDetails[bi.IPStr]; !active || current.UnbanTime.Equal(targetUnban) {
						a.retryQueue[bi.IPStr] = bi
					}
					a.mu.Unlock()
				} else {
					atomic.AddUint64(&a.evictionCount, 1)

					a.mu.RLock()
					fresh, exists := a.bannedDetails[bi.IPStr]
					a.mu.RUnlock()

					if exists && fresh.UnbanTime.After(targetUnban) {
						_ = exec.Command(cmd, "-I", "INPUT", "-s", bi.IPStr, "-j", "DROP").Run()
						log.Printf("[RACE-RESOLVED] Замечена гонка для %s. Правило ядра мгновенно восстановлено.\n", bi.IPStr)
					}
				}
			}(evictedInfo, evictedInfo.UnbanTime)
		}
	}
	a.mu.Unlock()

	cmd := "iptables"
	if !info.IsV4 { cmd = "ip6tables" }
	if err := exec.Command(cmd, "-I", "INPUT", "-s", info.IPStr, "-j", "DROP").Run(); err != nil {
		log.Printf("[ERROR] Ошибка выполнения %s для %s: %v\n", cmd, info.IPStr, err)
		return
	}

	a.mu.Lock()
	if info.IsV4 {
		a.bannedIPv4[info.V4Key] = info.UnbanTime
	} else {
		a.bannedIPv6[info.V6Key] = info.UnbanTime
	}
	a.bannedDetails[info.IPStr] = info
	delete(a.retryQueue, info.IPStr)
	a.mu.Unlock()

	log.Printf("[BANNED] 🚨 IP %s заблокирован на %v.\n", info.IPStr, a.banDuration)
}

func (a *AntiDDoS) unbanLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var expiredIPs []BanInfo

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expiredIPs = expiredIPs[:0]
			now := time.Now()

			a.mu.RLock()
			for _, info := range a.bannedDetails {
				if !info.Unbanning && now.After(info.UnbanTime) {
					expiredIPs = append(expiredIPs, info)
				}
			}
			a.mu.RUnlock()

			for _, info := range expiredIPs {
				a.unbanIP(info.IPStr, info.UnbanTime)
			}
		}
	}
}

func (a *AntiDDoS) unbanIP(ip string, targetUnbanTime time.Time) {
	a.mu.Lock()
	currentInfo, exists := a.bannedDetails[ip]
	if !exists || currentInfo.Unbanning || !currentInfo.UnbanTime.Equal(targetUnbanTime) {
		a.mu.Unlock()
		return
	}

	currentInfo.Unbanning = true
	a.bannedDetails[ip] = currentInfo
	a.mu.Unlock()

	cmd := "iptables"
	if !currentInfo.IsV4 { cmd = "ip6tables" }
	err := exec.Command(cmd, "-D", "INPUT", "-s", ip, "-j", "DROP").Run()

	a.mu.Lock()
	doubleCheck, stillExists := a.bannedDetails[ip]
	
	if !stillExists || !doubleCheck.UnbanTime.Equal(targetUnbanTime) {
		if stillExists {
			doubleCheck.Unbanning = false
			a.bannedDetails[ip] = doubleCheck
		}
		a.mu.Unlock()
		return 
	}

	if err != nil {
		log.Printf("[WARN] Сбой разбана %s (%v). Отправлен в карантин.\n", ip, err)
		a.retryQueue[ip] = currentInfo
	}

	if currentInfo.IsV4 {
		delete(a.bannedIPv4, currentInfo.V4Key)
	} else {
		delete(a.bannedIPv6, currentInfo.V6Key)
	}
	delete(a.bannedDetails, ip)
	a.mu.Unlock()

	if err == nil {
		log.Printf("[UNBANNED] IP %s успешно разблокирован.\n", ip)
	}
}

func (a *AntiDDoS) retryCleanupLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var localQueue []BanInfo
	var deadIPs []string

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			localQueue = localQueue[:0]
			deadIPs = deadIPs[:0]

			a.mu.RLock()
			for _, info := range a.retryQueue {
				localQueue = append(localQueue, info)
			}
			a.mu.RUnlock()

			for _, info := range localQueue {
				a.mu.Lock()
				
				if activeInfo, isBannedAgain := a.bannedDetails[info.IPStr]; isBannedAgain {
					if activeInfo.Unbanning || activeInfo.UnbanTime.After(info.UnbanTime) {
						delete(a.retryQueue, info.IPStr)
						a.mu.Unlock()
						continue
					}
				}

				cmd := "iptables"
				if !info.IsV4 { cmd = "ip6tables" }

				if err := exec.Command(cmd, "-D", "INPUT", "-s", info.IPStr, "-j", "DROP").Run(); err == nil {
					log.Printf("[CLEANUP] Карантин: Зомби-правило для %s удалено.\n", info.IPStr)
					delete(a.retryQueue, info.IPStr)
					a.mu.Unlock()
				} else {
					info.RetryCount++
					if info.RetryCount >= MaxRetries {
						deadIPs = append(deadIPs, info.IPStr)
						delete(a.retryQueue, info.IPStr)
					} else {
						a.retryQueue[info.IPStr] = info
					}
					a.mu.Unlock()
				}
			}

			if len(deadIPs) > 0 {
				log.Printf("[WARN-GHOST] %d хостов превысили лимит ретраев в карантине: [%s]. Требуется ручная проверка iptables!\n", 
					len(deadIPs), strings.Join(deadIPs, ", "))
			}
		}
	}
}

func (a *AntiDDoS) cleanupAllBans() {
	a.mu.RLock()
	snapshotActive := make([]BanInfo, 0, len(a.bannedDetails))
	for _, info := range a.bannedDetails { snapshotActive = append(snapshotActive, info) }
	
	snapshotZombie := make([]BanInfo, 0, len(a.retryQueue))
	for _, info := range a.retryQueue { snapshotZombie = append(snapshotZombie, info) }
	a.mu.RUnlock()

	activeErr, zombieErr := 0, 0

	for _, info := range snapshotActive {
		cmd := "iptables"
		if !info.IsV4 { cmd = "ip6tables" }
		if err := exec.Command(cmd, "-D", "INPUT", "-s", info.IPStr, "-j", "DROP").Run(); err != nil { activeErr++ }
	}

	for _, info := range snapshotZombie {
		cmd := "iptables"
		if !info.IsV4 { cmd = "ip6tables" }
		if err := exec.Command(cmd, "-D", "INPUT", "-s", info.IPStr, "-j", "DROP").Run(); err != nil { zombieErr++ }
	}

	log.Printf("[CLEANUP] Снято активных правил: %d из %d (Ошибок: %d)\n", len(snapshotActive)-activeErr, len(snapshotActive), activeErr)
	log.Printf("[CLEANUP] Снято зомби-правил: %d из %d (Ошибок: %d)\n", len(snapshotZombie)-zombieErr, len(snapshotZombie), zombieErr)
}

func (a *AntiDDoS) initWhitelist(ips []string) {
	for _, rawItem := range ips {
		rawItem = strings.TrimSpace(rawItem)
		if rawItem == "" { continue }

		if strings.Contains(rawItem, "/") {
			_, ipNet, err := net.ParseCIDR(rawItem)
			if err == nil {
				a.whitelistNets = append(a.whitelistNets, ipNet)
				log.Printf("[INIT] Whitelist CIDR подсеть: %s\n", ipNet.String())
			}
			continue
		}

		parsedIP := net.ParseIP(rawItem)
		if parsedIP == nil { continue }

		if v4 := parsedIP.To4(); v4 != nil {
			a.whitelistV4[ip4Attr(binary.BigEndian.Uint32(v4))] = true
			log.Printf("[INIT] Whitelist IPv4: %s\n", parsedIP.String())
		} else if a.hasIPv6 {
			var key ip6Attr
			copy(key[:], parsedIP.To16())
			a.whitelistV6[key] = true
			log.Printf("[INIT] Whitelist IPv6: %s\n", parsedIP.String())
		}
	}
}

func hashIPv6(key ip6Attr) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(key[:])
	return h.Sum32()
}

func byteToIPv4Str(ip uint32) string {
	return net.IP([]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}).String()
}

func (a *AntiDDoS) startMetricsServer() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		a.mu.RLock()
		activeBans := len(a.bannedDetails)
		zombies := len(a.retryQueue)
		a.mu.RUnlock()

		fmt.Fprintf(w, "# HELP lazyguard_active_bans Текущее количество активных банов в памяти\n")
		fmt.Fprintf(w, "# TYPE lazyguard_active_bans gauge\n")
		fmt.Fprintf(w, "lazyguard_active_bans %d\n", activeBans)

		fmt.Fprintf(w, "# HELP lazyguard_zombie_quarantine Текущее количество правил в карантине\n")
		fmt.Fprintf(w, "# TYPE lazyguard_zombie_quarantine gauge\n")
		fmt.Fprintf(w, "lazyguard_zombie_quarantine %d\n", zombies)

		fmt.Fprintf(w, "# HELP lazyguard_evictions_total Общее количество успешных досрочных вытеснений из пула\n")
		fmt.Fprintf(w, "# TYPE lazyguard_evictions_total counter\n")
		fmt.Fprintf(w, "lazyguard_evictions_total %d\n", atomic.LoadUint64(&a.evictionCount))

		fmt.Fprintf(w, "# HELP lazyguard_eviction_errors_total Общее количество сбоев CLI при вытеснении (ушли в карантин)\n")
		fmt.Fprintf(w, "# TYPE lazyguard_eviction_errors_total counter\n")
		fmt.Fprintf(w, "lazyguard_eviction_errors_total %d\n", atomic.LoadUint64(&a.evictionErrors))

		fmt.Fprintf(w, "# HELP lazyguard_dropped_packets_estimated Оценочное количество сброшенных ядром пакетов забаненных IP\n")
		fmt.Fprintf(w, "# TYPE lazyguard_dropped_packets_estimated counter\n")
		fmt.Fprintf(w, "lazyguard_dropped_packets_estimated %d\n", atomic.LoadUint64(&a.packetDropEst))
	})

	// Локальный запуск на 127.0.0.1 для максимальной безопасности pprof/метрики
	localAddr := "127.0.0.1" + MetricsAddr
	log.Printf("[INIT] Сервер метрик и pprof ЗАЩИЩЕН и запущен локально на %s\n", localAddr)
	if err := http.ListenAndServe(localAddr, nil); err != nil {
		log.Printf("[WARN] Не удалось запустить HTTP-сервер: %v\n", err)
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists { return value }
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil { return intVal }
	}
	return fallback
}
