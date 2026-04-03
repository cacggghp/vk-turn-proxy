# VK/WB TURN Proxy
[English version](README.en.md)

Проброс трафика WireGuard/Hysteria через TURN сервера VK звонков или WB Stream. Пакеты шифруются DTLS 1.2, затем параллельными потоками через TCP или UDP отправляются на TURN сервер по протоколу STUN ChannelData. Оттуда по UDP отправляются на ваш сервер, где расшифровываются и передаются в WireGuard. Логин/пароль от TURN генерируются из ссылки на звонок.

## Возможности

- **VK Calls** — TURN credentials от VK API с автоматическим решением капчи (Not Robot)
- **WB Stream** — TURN credentials от WB Stream API (LiveKit ICE)
- **Кеширование** — 10 минут с общим кешем на 4 потока
- **DTLS-обфускация** — обход DPI через DTLS-туннель
- **Множественные соединения** — до N параллельных подключений к TURN

**Обновление: Многопользовательский прокси-сервер**
Текущая реализация поддерживает одновременную работу нескольких пользователей через один прокси-сервер.
- **Идентификация сессий:** Клиент генерирует уникальный 16-байтный UUID при старте.
- **Агрегация потоков:** Сервер группирует все входящие DTLS-соединения от одного клиента по его UUID.
- **Стабильный бэкенд:** Для каждой сессии создается ровно одно UDP-соединение с WireGuard-сервером. Это предотвращает проблему "прыгающих портов" (endpoint thrashing) и повышает стабильность.
- **Балансировка:** Исходящий трафик от сервера к клиенту распределяется между всеми активными DTLS-потоками пользователя (Round-Robin).

Только для учебных целей!

## Структура клиента

```
client/
├── credentials.go    # Общий кеш credentials, сериализация запросов
├── vk.go             # VK API: Token 1→4 chain, HTTP-запросы
├── vk_captcha.go     # VK Captcha: PoW solving, Not Robot flow
├── wb.go             # WB Stream: guest register → room → LiveKit ICE
└── main.go           # DTLS/TURN соединения, CLI, основной цикл
```

## Настройка

Нам понадобится:
1. Ссылка на действующий ВК звонок: создаём свой (нужен аккаунт вк), или гуглим `"https://vk.com/call/join/"`.
   Ссылка действительна вечно, если не нажимать "завершить звонок для всех"
2. VPS с установленным WireGuard
3. Для андроида: скачать Termux из F-Droid

### Сервер

```
./server -listen 0.0.0.0:56000 -connect 127.0.0.1:<порт wg>
```

### Клиент

#### Android

**Рекомендуемый способ:**
Использовать нативное Android-приложение [wireguard-turn-android](https://github.com/kiper292/wireguard-turn-android). Это модифицированный WireGuard клиент со встроенным TURN.

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
Копируем бинарник в локальную папку, даём права на исполнение:
```
cp /sdcard/Download/client-android ./
chmod 777 ./client-android
```

**VK режим:**
```
./client-android -peer <ip сервера wg>:56000 -vk-link <VK ссылка> -listen 127.0.0.1:9000
```

**WB режим:**
```
./client-android -wb -peer <ip сервера wg>:56000 -listen 127.0.0.1:9000
```

Дополнительные флаги:
- `-session-id <hex>`: установить фиксированный ID сессии (32 символа hex).
- `-n <число>`: количество подключений к TURN (по умолчанию 4).
- `-udp`: использовать UDP для TURN (по умолчанию TCP).
- `-turn <ip>`: переопределить адрес TURN сервера.
- `-port <port>`: переопределить порт TURN сервера.
- `-no-dtls`: без DTLS-обфускации (может привести к бану).

#### Linux

В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280

Скрипт будет добавлять маршруты к нужным ip:

```
./client-linux -peer <ip сервера wg>:56000 -vk-link <VK ссылка> -listen 127.0.0.1:9000 | sudo routes.sh
```

```
./client-linux -wb -peer <ip сервера wg>:56000 -listen 127.0.0.1:9000 | sudo routes.sh
```

Не включайте впн, пока программа не установит соединение! В отличие от андроида, здесь часть запросов будет идти через впн (dns и запрос подключения к turn)

#### Windows

В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280

В PowerShell от Администратора (чтобы скрипт прописывал маршруты):

```
./client.exe -peer <ip сервера wg>:56000 -vk-link <VK ссылка> -listen 127.0.0.1:9000 | routes.ps1
```

```
./client.exe -wb -peer <ip сервера wg>:56000 -listen 127.0.0.1:9000 | routes.ps1
```

Не включайте впн, пока программа не установит соединение! В отличие от андродида, здесь часть запросов будет идти через впн (dns и запрос подключения к turn)

### Если не работает

С помощью опции `-turn` можно указать адрес TURN сервера вручную. Это должен быть сервер ВК, Макса или Одноклассников (ссылка вк) или WB Stream (режим -wb).

Если не работает TCP, попробуйте добавить флаг `-udp`.

Добавьте флаг `-n 1` для более стабильного подключения в 1 поток (ограничение 5 Мбит/с для ВК)

## VK Auth Flow

1. **Token 1** — анонимный токен (`login.vk.ru`)
2. **getCallPreview** — превью звонка (опционально)
3. **Token 2** — анонимный токен для звонка (`api.vk.ru`)
   - При капче → PoW solving → retry
4. **Token 3** — OK session key (`calls.okcdn.ru`)
5. **Token 4** — TURN credentials (`calls.okcdn.ru`)

## WB Auth Flow

1. **Guest register** — регистрация гостя (`stream.wb.ru`)
2. **Create room** — создание комнаты
3. **Join room** — подключение к комнате
4. **Get token** — получение roomToken
5. **LiveKit ICE** — WebSocket к LiveKit, protobuf парсинг TURN

## Кеширование

- TTL: **10 минут** (safety margin 60 секунд)
- Один кеш на **4 потока** (`streamID / 4`)
- Fast path через `RLock`
- Сериализация fetch через глобальный `fetchMu`

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
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "protocol": "http",
            "listen": "127.0.0.1",
            "port": 8080,
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
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
                "destOverride": [
                    "http",
                    "tls"
                ]
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

С флагом `-no-dtls` можно отправлять пакеты без обфускации DTLS и подключаться к обычным серверам Wireguard. Может привести к бану от ВК/WB.

Спасибо https://github.com/KillTheCensorship/Turnel за часть кода :)

Функционал WB Stream основан на проекте https://github.com/jaykaiperson/lionheart
