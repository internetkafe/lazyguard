#!/bin/bash
# LazyGuard Installation Script

# Завершить выполнение при любой ошибке
set -e

echo "[*] Обновление системы и установка системных зависимостей..."
apt update && apt install -y git libpcap-dev iptables conntrack dsniff curl build-essential

echo "[*] Установка Go 1.22.11..."
# Удаляем старую версию, если есть
rm -rf /usr/local/go
curl -L https://go.dev/dl/go1.22.11.linux-amd64.tar.gz -o go.tar.gz
tar -C /usr/local -xzf go.tar.gz
rm go.tar.gz

# Добавляем Go в PATH для текущей сессии
export PATH=$PATH:/usr/local/go/bin

# Добавляем PATH в .bashrc, если его там еще нет
if ! grep -qxF 'export PATH=$PATH:/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo "[*] PATH обновлен в ~/.bashrc"
fi

echo "[*] Настройка зависимостей проекта..."
# Проверяем, инициализирован ли модуль
if [ ! -f "go.mod" ]; then
    echo "[*] go.mod не найден, инициализируем модуль..."
    go mod init github.com/internetkafe/lazyguard
fi

# Скачиваем зависимости и обновляем go.mod
go mod tidy

echo "[*] Сборка LazyGuard..."
go build -o brainguard main.go

echo "=================================================="
echo "[!] Установка успешно завершена!"
echo "[!] Для запуска используйте: sudo ./brainguard"
echo "[!] Не забудьте настроить .env файл перед запуском."
echo "=================================================="
