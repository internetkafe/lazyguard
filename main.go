package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
)

type AntiDDoS struct {
	mu            sync.Mutex
	ipCounts      map[string]int
	bannedIPs     map[string]time.Time
	interfaceName string
	targetPort    string
	packetLimit   int
	checkInterval time.Duration
	banDuration   time.Duration
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Предупреждение: .env файл не найден, используются дефолтные настройки")
	}

	anti := &AntiDDoS{
		ipCounts:      make(map[string]int),
		bannedIPs:     make(map[string]time.Time),
		interfaceName: getEnv("INTERFACE", "eth0"),
		targetPort:    getEnv("TARGET_PORT", "443"),
		packetLimit:   getEnvInt("PACKET_LIMIT", 250),
		checkInterval: time.Duration(getEnvInt("CHECK_INTERVAL_SEC", 2)) * time.Second,
		banDuration:   time.Duration(getEnvInt("BAN_TIME_SEC", 3600)) * time.Second,
	}

	fmt.Println("==================================================")
	fmt.Println("    BrainGuard v1.1 - Мониторинг и Защита         ")
	fmt.Println("==================================================")
	fmt.Printf("[*] Интерфейс: %s | Порт: %s\n", anti.interfaceName, anti.targetPort)
	fmt.Printf("[*] Порог бана: > %d пак. за %v\n", anti.packetLimit, anti.checkInterval)
	fmt.Printf("[*] Порог подозрительности: > %d пак. за %v\n", anti.packetLimit/2, anti.checkInterval)
	fmt.Println("--------------------------------------------------")

	go anti.analyzerLoop()
	go anti.unbanLoop()

	handle, err := pcap.OpenLive(anti.interfaceName, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка открытия интерфейса: %v", err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("dst port %s", anti.targetPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("[FATAL] Ошибка установки BPF-фильтра: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		anti.processPacket(packet)
	}
}

func (a *AntiDDoS) processPacket(packet gopacket.Packet) {
	var srcIP string

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		srcIP = ip6.SrcIP.String()
	}

	if srcIP == "" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, banned := a.bannedIPs[srcIP]; banned {
		return
	}

	a.ipCounts[srcIP]++
}

func (a *AntiDDoS) analyzerLoop() {
	ticker := time.NewTicker(a.checkInterval)
	for range ticker.C {
		a.mu.Lock()
		
		var ipsToBan []string
		// Пороговое значение подозрительности (половина от лимита бана)
		suspiciousThreshold := a.packetLimit / 2

		for ip, count := range a.ipCounts {
			if count > a.packetLimit {
				ipsToBan = append(ipsToBan, ip)
			} else if count > suspiciousThreshold {
				// Включаем логирование подозрительных IP, которые еще не наглые для бана
				log.Printf("[SUSPICIOUS] IP %s ведет себя странно: %d пакетов за %v (Порог: %d)\n", 
					ip, count, a.checkInterval, suspiciousThreshold)
			}
		}
		
		a.ipCounts = make(map[string]int)
		a.mu.Unlock()

		for _, ip := range ipsToBan {
			a.banIP(ip)
		}
	}
}

func (a *AntiDDoS) banIP(ip string) {
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("[ERROR] Не удалось забанить %s: %v\n", ip, err)
		return
	}

	a.mu.Lock()
	a.bannedIPs[ip] = time.Now().Add(a.banDuration)
	a.mu.Unlock()

	log.Printf("[BANNED] 🚨 Жесткий флуд! IP %s отправлен в бан на уровне ядра.\n", ip)
}

func (a *AntiDDoS) unbanLoop() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		a.mu.Lock()
		now := time.Now()
		var ipsToUnban []string

		for ip, unbanTime := range a.bannedIPs {
			if now.After(unbanTime) {
				ipsToUnban = append(ipsToUnban, ip)
			}
		}
		a.mu.Unlock()

		for _, ip := range ipsToUnban {
			a.unbanIP(ip)
		}
	}
}

func (a *AntiDDoS) unbanIP(ip string) {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("[ERROR] Не удалось разблокировать %s: %v\n", ip, err)
		return
	}

	a.mu.Lock()
	delete(a.bannedIPs, ip)
	a.mu.Unlock()

	log.Printf("[UNBANNED] Время блокировки вышло. IP %s разбанен.\n", ip)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}
