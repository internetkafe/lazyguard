#!/bin/bash
# LazyGuard Installation Script

set -e

echo "[*] Обновление системы и установка зависимостей..."
apt update && apt install -y git libpcap-dev iptables conntrack dsniff curl build-essential

echo "[*] Установка Go 1.22.11..."
rm -rf /usr/local/go
curl -L https://go.dev/dl/go1.22.11.linux-amd64.tar.gz -o go.tar.gz
tar -C /usr/local -xzf go.tar.gz
rm go.tar.gz

export PATH=$PATH:/usr/local/go/bin

echo "[*] Настройка проекта..."
# Если уже клонировали, идем в директорию
[ -d "lazyguard" ] && cd lazyguard

go mod init github.com/internetkafe/lazyguard
go mod tidy

echo "[*] Сборка LazyGuard..."
go build -o brainguard main.go

echo "[!] Установка завершена!"
echo "[!] Теперь запустите: sudo ./brainguard"
