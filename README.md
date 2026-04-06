# Good TURN

Проброс трафика WireGuard/Hysteria через TURN сервера VK звонков или ~~Яндекс телемоста~~. Пакеты шифруются DTLS 1.2, затем параллельными потоками через TCP или UDP отправляются на TURN сервер по протоколу STUN ChannelData. Оттуда по UDP отправляются на ваш сервер, где расшифровываются и передаются в WireGuard. Логин/пароль от TURN генерируются из ссылки на звонок.

Только для учебных целей!

## Похожие проекты
- https://github.com/MYSOREZ/vk-turn-proxy-android - клиент для андроида
- https://github.com/kiper292/wireguard-turn-android - клиент для андроида интегрированный в WireGuard
- https://github.com/WINGS-N/WINGSV - клиент для андроида с One UI, WireGuard, раздачей VPN с root
- https://github.com/nullcstring/turnbridge - клиент для IOS
- https://github.com/Urtyom-Alyanov/turn-proxy - реализация на Rust
- https://github.com/jaykaiperson/lionheart - аналог для https://stream.wb.ru (статья: https://habr.com/ru/articles/1017410/)
- https://github.com/kulikov0/whitelist-bypass - проброс через медиасервер SFU ВК и Яндекс Телемоста

## Настройка

Нам понадобится:

1. Ссылка на действующий ВК звонок: создаём свой (нужен аккаунт вк), или гуглим `"https://vk.com/call/join/"`.
   Ссылка действительна вечно, если не нажимать "завершить звонок для всех"
2. Или ссыска на звонок Яндекс телемоста: `"https://telemost.yandex.ru/j/"`. Её лучше не гуглить, так как видно подключение к конференции
3. VPS с установленным WireGuard
4. Для андроида: скачать Termux из F-Droid

### Сервер

<details><summary>Рекомендуется tmux</summary>

На сервере запустить tmux:

```bash
# Создание сессии tmux
tmux new -s vkturn
```

Внутри сессии tmux запустить команду сервера ниже. Далее нажать `Ctrl+B` `D`, чтобы свернуть сессию, не завершая её. Прокси процесс останется запущенным, сервер будет доступен для новых команд или безопасного выхода из него.

```bash
# Войти в ранее созданную сессию tmux
tmux a -t vkturn
```

</details>

Скачать бинарник, в данном примере используется самый популярный сервер `server-linux-amd64`:

```bash
# Скачать бинарник
curl -L -o server https://github.com/cacggghp/vk-turn-proxy/releases/latest/download/server-linux-amd64 && chmod +x server
```

```bash
# Запуск сервера
./server -listen 0.0.0.0:56000 -connect 127.0.0.1:<порт wg>
```
#### Установка демона
На сервере в файле `/etc/systemd/system/vk-turn-proxy.service`
```
[Unit]
Description=VK Turn Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/vk-turn-proxy/server-linux-amd64 -listen 0.0.0.0:56000 -connect 127.0.0.1:<wg_port>
KillMode=process
Restart=always
RestartSec=5
User=nobody
Group=nogroup
StandardOutput=append:/var/log/vk-turn-proxy/vk-turn-proxy.log
StandardError=append:/var/log/vk-turn-proxy/vk-turn-proxy_error.log
SyslogIdentifier=vk-turn-proxy

[Install]
WantedBy=multi-user.target
```
Где `/opt/vk-turn-proxy/server-linux-amd64` - путь к файлу, `<wg_port>` - порт сервера wg
```
systemctl daemon-reload
systemctl enable vk-turn-proxy.service
systemctl start vk-turn-proxy.service
```
#### Docker

Образ Docker публикуется в GitHub Container Registry:

```
docker pull ghcr.io/cacggghp/vk-turn-proxy:latest
docker tag ghcr.io/cacggghp/vk-turn-proxy:latest vkt
```

Для Linux-сервера, где `xray` или WireGuard слушает локально, удобнее запускать через host network:

```
docker run --rm --network host -e CONNECT_ADDR=127.0.0.1:<порт wg> vkt
```

Если нужен bridge mode:

```
docker run --rm -p 56000:56000/udp -e CONNECT_ADDR=<ip хоста>:<порт wg> vkt
```

Сборка образа вручную:

```
git clone https://github.com/cacggghp/vk-turn-proxy.git
cd vk-turn-proxy
docker build -t vk-turn-proxy .
```

Переменная окружения **CONNECT_ADDR** — адрес WireGuard (обязательный), например `192.168.1.10:51820`.

Пример запуска:

```
docker run -p 56000:56000/udp -e CONNECT_ADDR=192.168.1.10:51820 vk-turn-proxy
```

### Клиент

#### Android

**Рекомендуемый способ:**
Использовать нативное Android-приложение [vk-turn-proxy-android](https://github.com/MYSOREZ/vk-turn-proxy-android).

- В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280
- **Добавляем приложение в исключения WireGuard. Нажимаем "сохранить".**

**Альтернативный способ (через Termux):**

- В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280
- **Добавляем Termux в исключения WireGuard. Нажимаем "сохранить".**
  В Termux:

```
termux-wake-lock
```

Телефон не будет уходить в глубокий сон, так что на ночь ставьте на зарядку. Чтобы отключить:

```
termux-wake-unlock
```

Скачиваем бинарник в локальную папку, даём права на исполнение, в команде указаана самая популярная архитектура `client-android-arm64`:

```bash
curl -L -o client https://github.com/cacggghp/vk-turn-proxy/releases/latest/download/client-android-arm64 && chmod +x client
```

Запускаем:

```
./client -listen 127.0.0.1:9000 -peer <ip сервера wg>:56000 -vk-link <VK ссылка>
```

Или

```
./client -udp -turn 5.255.211.241 -peer <ip сервера wg>:56000 -yandex-link <Ya ссылка> -listen 127.0.0.1:9000
```

**Если после включения VPN в терминале вылезают ошибки DNS, попробуйте в Wireguard включить VPN только для нужных приложений.**

#### IOS
- https://github.com/cacggghp/vk-turn-proxy/issues/76
#### Linux

В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280

Скрипт будет добавлять маршруты к нужным ip:

```
./client-linux -peer <ip сервера wg>:56000 -vk-link <VK ссылка> -listen 127.0.0.1:9000 | sudo routes.sh
```

```
./client-linux -udp -turn 5.255.211.241 -peer <ip сервера wg>:56000 -yandex-link <Ya ссылка> -listen 127.0.0.1:9000 | sudo routes.sh
```

Не включайте впн, пока программа не установит соединение! В отличие от андроида, здесь часть запросов будет идти через впн (dns и запрос подключения к turn)

#### Windows

В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280

В PowerShell от Администратора (чтобы скрипт прописывал маршруты):

```
./client.exe -peer <ip сервера wg>:56000 -vk-link <VK ссылка> -listen 127.0.0.1:9000 | routes.ps1
```

```
./client.exe -udp -turn 5.255.211.241 -peer <ip сервера wg>:56000 -yandex-link <Ya ссылка> -listen 127.0.0.1:9000 | routes.ps1
```

Не включайте впн, пока программа не установит соединение! В отличие от андроида, здесь часть запросов будет идти через впн (dns и запрос подключения к turn)

### Если не работает

С помощью опции `-turn` можно указать адрес TURN сервера вручную. Это должен быть сервер ВК, Макса или Одноклассников (ссылка вк) или Яндекса (ссылка яндекса). Возможно потом составлю список.

Если не работает VLESS, попробуйте добавить флаг `-udp`.

Добавьте флаг `-n 1` для более стабильного подключения в 1 поток (ограничение 5 Мбит/с для ВК)

## Яндекс телемост

**UPD. ТЕЛЕМОСТ ЗАКРЫЛИ**

В отличие от ВК, сервера яндекса не ограничивают скорость, так что по умолчанию стоит `-n 1`. Увеличение этого числа может привести к временной блокировке по IP из-за переполнения конференции фейковыми участниками.

В режиме `-udp` скорость обычно больше

Большинство диапазонов IP TURN серверов Яндекса не работают, указывайте вручную через `-turn`

<details>
    <summary>
        Рабочие IP
    </summary>

    5.255.211.241
    5.255.211.242
    5.255.211.243
    5.255.211.245
    5.255.211.246

</details>
Спасибо https://github.com/KillTheCensorship/Turnel за часть кода :)

## v2ray

Вместо WireGuard можно использовать любое V2Ray-ядро которое его поддерживает (например, xray или sing-box) и любой V2Ray-клиент который использует это ядро (например, v2rayN или v2rayNG). С помощью их вы сможете добавить больше входящих интерфейсов (например, SOCKS) и реализовать точечный роутинг.

Пример конфигов:

<details>

<summary>
Клиент
</summary>

```json
{
  "inbounds": [
    {
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 1080,
      "settings": {
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "protocol": "http",
      "listen": "127.0.0.1",
      "port": 8080,
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "wireguard",
      "settings": {
        "secretKey": "<client secret key>",
        "peers": [
          {
            "endpoint": "127.0.0.1:9000",
            "publicKey": "<server public key>"
          }
        ],
        "domainStrategy": "ForceIPv4",
        "mtu": 1280
      }
    }
  ]
}
```

</details>

<details>

<summary>
Сервер
</summary>

```json
{
  "inbounds": [
    {
      "protocol": "wireguard",
      "listen": "0.0.0.0",
      "port": 51820,
      "settings": {
        "secretKey": "<server secret key>",
        "peers": [
          {
            "publicKey": "<client public key>"
          }
        ],
        "mtu": 1280
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    }
  ]
}
```

</details>

## VLESS-режим

Если WireGuard блокируется DPI, можно использовать VLESS через флаг `-vless`. В этом режиме вместо UDP-пакетов пробрасываются TCP-соединения через TURN-туннель с помощью KCP и smux.

### Настройка
1. На VPS установить Xray с VLESS inbound
2. Запустить `server` с флагом `-vless`
3. На клиенте запустить `client` с флагом `-vless`
4. Настроить Xray/v2rayN клиент с VLESS outbound на `127.0.0.1:9000`

### Сервер (VPS)
```
./server -listen 0.0.0.0:56000 -connect 127.0.0.1:443 -vless
```

#### Docker
```
docker run -p 56000:56000/udp -e CONNECT_ADDR=127.0.0.1:443 -e VLESS_MODE=true vk-turn-proxy
```

### Клиент
```
./client -peer <ip сервера>:56000 -vk-link <VK ссылка> -listen 127.0.0.1:9000 -vless
```

<details>

<summary>
Xray клиент (config.json)
</summary>

```json
{
    "inbounds": [
        {
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": 1080,
            "settings": {
                "udp": true
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "127.0.0.1",
                        "port": 9000,
                        "users": [
                            {
                                "id": "<UUID>",
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }
    ]
}
```

</details>

<details>

<summary>
Xray сервер (config.json)
</summary>

```json
{
    "inbounds": [
        {
            "protocol": "vless",
            "listen": "127.0.0.1",
            "port": 443,
            "settings": {
                "clients": [
                    {
                        "id": "<тот же UUID>",
                        "level": 0
                    }
                ],
                "decryption": "none"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            }
        }
    ]
}
```

</details>


## Direct mode

С флагом `-no-dtls` можно отправлять пакеты без обфускации DTLS и подключаться к обычным серверам Wireguard. Может привести к бану от вк/яндекса.

