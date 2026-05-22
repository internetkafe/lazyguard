#!/bin/bash
# LazyGuard Installation Script

set -e

# 1. Обновление и установка зависимостей
echo "[*] Обновление системы и установка зависимостей..."
apt update && apt install -y git libpcap-dev iptables conntrack dsniff curl build-essential

# 2. Установка Go 1.22.11
echo "[*] Установка Go 1.22.11..."
rm -rf /usr/local/go
curl -L https://go.dev/dl/go1.22.11.linux-amd64.tar.gz -o go.tar.gz
tar -C /usr/local -xzf go.tar.gz
rm go.tar.gz

# 3. Настройка переменных окружения
export PATH=$PATH:/usr/local/go/bin

if ! grep -qxF 'export PATH=$PATH:/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo "[*] PATH обновлен в ~/.bashrc"
fi

# 4. Сборка проекта
echo "[*] Настройка проекта и сборка..."
# Если скрипт запускается из корня проекта, инициализируем модули
if [ ! -f "go.mod" ]; then
    go mod init github.com/internetkafe/lazyguard
fi

go mod tidy
go build -o brainguard main.go

echo "[!] Установка завершена!"
echo "[!] Используйте 'sudo ./brainguard' для запуска."
echo "[!] Примените изменения PATH командой: source ~/.bashrc"
