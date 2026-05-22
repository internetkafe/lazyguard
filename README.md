 # LazyGuard

**LazyGuard** — это высокопроизводительный анти-DDoS фильтр на языке Go, предназначенный для защиты сетевых сервисов (Xray, VLESS, VMess и др.) на уровне ядра Linux.

## Особенности
*   **Netfilter RAW Protection**: Блокировка пакетов до того, как они попадут в TCP-стек.
*   **Connection Hijacking**: Агрессивный сброс существующих сокетов через `conntrack` и `tcpkill`.
*   **Shard Counters**: Масштабируемая обработка пакетов с использованием шардирования.
*   **Metrics**: Мониторинг в реальном времени через `/metrics` (порт 9100).
*   **Self-Protection**: Автоматическая проверка локальных IP для исключения их из банов.

## Быстрый старт

### Установка
```bash
git clone https://github.com/internetkafe/lazyguard.git
cd lazyguard
chmod +x install.sh
sudo ./install.sh
