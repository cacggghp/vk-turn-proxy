<div align="center">
  <h1>🛡️ Good TURN</h1>
  <p>
    <b>Проброс WireGuard / Hysteria через TURN серверы VK Звонков или Яндекс Телемоста</b>
  </p>
  <p>
    <a href="https://github.com/Mat1RX/vk-turn-proxy/releases">
      <img src="https://img.shields.io/github/v/release/Mat1RX/vk-turn-proxy?style=flat-square&color=blue" alt="Release">
    </a>
    <a href="https://aur.archlinux.org/packages/vk-turn-proxy-server-bin">
      <img src="https://img.shields.io/aur/version/vk-turn-proxy-server-bin?style=flat-square&color=1793d1&logo=archlinux" alt="AUR">
    </a>
    <a href="https://golang.org/">
      <img src="https://img.shields.io/badge/Language-Go-00ADD8?style=flat-square&logo=go" alt="Language">
    </a>
  </p>
</div>

---

> [!WARNING]
> **Внимание:** Проект создан **исключительно для учебных целей**! Автор не несет ответственности за использование данного ПО.

Трафик шифруется с помощью **DTLS 1.2** и передаётся через **STUN ChannelData**, маскируясь под легитимный WebRTC звонок в VK или Яндекс Телемост. Это делает его крайне сложным для выявления средствами DPI без блокировки всей инфраструктуры звонков платформы.

## ⚙️ Принцип работы

```mermaid
flowchart TD
    WG[WireGuard / Клиент] -->|UDP :9000| client[vk-turn-proxy-client]
    
    subgraph Client-Side
    client
    end
    
    client -.->|1. Fetch Credentials| API(VK / Yandex API)
    client -->|2. Обфускация DTLS 1.2| TURN
    
    subgraph Relay
    TURN((TURN Сервер\nVK / Яндекс))
    end
    
    TURN -->|3. STUN ChannelData\nUDP / TCP| server[vk-turn-proxy-server]
    
    subgraph Server-Side VPS
    server
    end
    
    server -->|UDP :51820| WGS[WireGuard Сервер]
```

1. **Получение TURN-credentials**: Прокси обращается к API VK/Яндекса через ссылку на звонок для получения одноразовых доступов. DNS-запросы идут через резолверы VK (`77.88.8.8`) и Google для обхода локальных блокировок.
2. **DTLS 1.2 — слой обфускации**: Создается DTLS соединение к серверу. Использование ключа (Pre-Shared Key) **обязательно** для защиты от MitM-атак и несанкционированного доступа. При использовании файла конфигурации (`.yaml`), ключ будет **сгенерирован автоматически**, если вы его не укажете! Пакеты WireGuard инкапсулируются внутри DTLS-потока, обфусцируя сигнатуры для DPI.
3. **TURN relay**: Передача пакетов идет на TURN-сервер платформы, а он уже перенаправляет их на ваш VPS. Для **VK** дополнительно открывается 16 параллельных потоков для обхода ограничения скорости в ~5 Мбит/с.
4. **Auto-Reconnect (Надежность)**: Клиент оснащен логикой *Exponential Backoff*. При падении интернета, прокси не вылетает, а бесшовно перестраивает туннель, гарантируя стабильную работу VPN.
5. **Dynamic Identity (Анти-фрод)**: При каждом новом подключении к API прокси генерирует уникальное реалистичное имя бота и подменяет `User-Agent` (случайно выбирая между профилями Safari, Mobile, Windows Chrome, Yandex), что позволяет полностью сливаться с легитимным трафиком и избегать автоматических блокировок.

---

## 🚀 Установка

### 🐧 Debian / Ubuntu (Systemd)

Самый популярный способ установки для VPS:

1. Скачайте последний релиз со страницы [Releases](https://github.com/cacggghp/vk-turn-proxy/releases).
2. Распакуйте и поместите бинарник в `/usr/local/bin/`:
```bash
sudo mv vk-turn-proxy-server /usr/local/bin/
sudo chmod +x /usr/local/bin/vk-turn-proxy-server
```
3. Создайте файл конфигурации:
```bash
sudo mkdir -p /etc/vk-turn-proxy
sudo nano /etc/vk-turn-proxy/server.yaml
```
4. Создайте Systemd сервис (`sudo nano /etc/systemd/system/vk-turn-proxy-server.service`):
```ini
[Unit]
Description=VK TURN Proxy Server
After=network.target

[Service]
ExecStart=/usr/local/bin/vk-turn-proxy-server -c /etc/vk-turn-proxy/server.yaml
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```
5. Запустите:
```bash
sudo systemctl enable --now vk-turn-proxy-server
```

### 🐳 Docker (сервер)

Вы можете развернуть серверную часть через Docker одним запуском:

```bash
docker pull ghcr.io/cacggghp/vk-turn-proxy:latest
docker run -d --restart unless-stopped -p 56000:56000/udp \
  -e CONNECT_ADDR=192.168.1.10:51820 \
  -e SECRET="my-strong-password" \
  --name vk-turn-proxy ghcr.io/cacggghp/vk-turn-proxy:latest
```

### 💙 Arch Linux (AUR)

В Arch Linux вы можете использовать AUR хелпер:

```bash
yay -S vk-turn-proxy-server-bin   # сервер
yay -S vk-turn-proxy-client-bin   # клиент
```

---

## 🛠 Использование

**Что вам понадобится:**
- **Ссылка на VK Звонок** (`https://vk.com/call/join/...`). Создайте свой звонок, ссылка действует вечно (если не завершить для всех).
- *Или* **Ссылка на Яндекс Телемост** (`https://telemost.yandex.ru/j/...`).
- **VPS** с установленным и настроенным WireGuard сервером.

### Запуск сервера

На сервере (вашем VPS) выполните:

```bash
# Через флаги:
./vk-turn-proxy-server -listen 0.0.0.0:56000 -connect 127.0.0.1:<порт wg> -secret "my-strong-password"

# ИЛИ через конфигурационный файл:
./vk-turn-proxy-server -c server.yaml.example
```

### Запуск клиента

> [!CAUTION]
> **Важно:** В конфигурации клиента WireGuard укажите `Endpoint = 127.0.0.1:9000` и `MTU = 1280`. Не подключайте VPN до того, как `vk-turn-proxy-client` успешно установит соединение! (Для Linux/Windows)

**🐧 Linux:**
```bash
# Через длинные флаги:
./vk-turn-proxy-client -peer <ip VPS>:56000 -vk-link <ссылка> -listen 127.0.0.1:9000 -secret "my-strong-password"

# ИЛИ через красивый конфигурационный файл:
./vk-turn-proxy-client -c client.yaml.example
```

**🪟 Windows** (PowerShell от имени Администратора):
```powershell
.\client.exe -c client.yaml.example
```

**📱 Android:** 
Лучше всего использовать адаптацию [vk-turn-proxy-android](https://github.com/MYSOREZ/vk-turn-proxy-android) или запустить клиентское ядро через Termux.

---

## 🎛 Флаги запуска клиента

| Флаг | Описание | По умолчанию |
|------|----------|--------------|
| `-c` | Путь к файлу конфигурации YAML (Например: `client.yaml`) | - |
| `-peer` | **Обязательный.** Адрес вашего сервера `host:port` | - |
| `-vk-link` | Ссылка-инвайт на VK Звонок | - |
| `-yandex-link` | Ссылка-инвайт на Яндекс Телемост | - |
| `-listen` | Локальный интерфейс и порт для прослушивания трафика VPN | `127.0.0.1:9000` |
| `-secret` | **Обязательный.** PSK-пароль. При запуске через `.yaml` файл генерируется **автоматически**, если не указан. | - |
| `-n` | Количество потоков TURN (рекомендуется `16` для VK, `1` для Яндекса) | `16` / `1` |
| `-udp` | Использовать UDP протокол для подключения к TURN | `false` (over TCP) |
| `-turn` | Указать IP TURN сервера вручную | - |
| `-no-dtls` | **Опасно.** Отключить слои обфускации (может привести к бану) | `false` |

---

## 🟡 Настройки для Яндекс Телемоста

> [!WARNING]
> **UPD: Сервис ТЕЛЕМОСТ почти ЗАКРЫЛИ**

Если вы все еще используете Я.Телемост, помните:
- По умолчанию следует использовать флаг `-n 1`, так как нет ограничений скорости.
- Увеличение числа `-n` может привести к бану по IP за обилие пустых (фейковых) подключений.
- Рекомендуется активировать флаг `-udp` в связке с конкретными IP адресами.

<details>
<summary><b>Список рабочих IP TURN серверов Яндекса</b> <i>(использовать с флагом <code>-turn</code>)</i></summary>

```text
5.255.211.241
5.255.211.242
5.255.211.243
5.255.211.245
5.255.211.246
```
</details>

---

## 🎭 Совместимость с V2Ray

Вместо WireGuard можно использовать `xray-core` или `sing-box`. Это позволит гибче настроить маршрутизацию (например, через SOCKS5 для точечного обхода блокировок). Примеры конфигураций:

<details>
<summary><b>💻 Клиент (xray)</b></summary>

```json
{
    "inbounds": [
        { "protocol": "socks", "listen": "127.0.0.1", "port": 1080,
          "settings": { "udp": true },
          "sniffing": { "enabled": true, "destOverride": ["http","tls"] } },
        { "protocol": "http", "listen": "127.0.0.1", "port": 8080,
          "sniffing": { "enabled": true, "destOverride": ["http","tls"] } }
    ],
    "outbounds": [
        { "protocol": "wireguard",
          "settings": {
              "secretKey": "<client secret key>",
              "peers": [{ "endpoint": "127.0.0.1:9000", "publicKey": "<server public key>" }],
              "domainStrategy": "ForceIPv4", "mtu": 1280
          }
        }
    ]
}
```
</details>

<details>
<summary><b>🌍 Сервер (xray)</b></summary>

```json
{
    "inbounds": [
        { "protocol": "wireguard", "listen": "0.0.0.0", "port": 51820,
          "settings": {
              "secretKey": "<server secret key>",
              "peers": [{ "publicKey": "<client public key>" }],
              "mtu": 1280
          },
          "sniffing": { "enabled": true, "destOverride": ["http","tls"] }
        }
    ],
    "outbounds": [
        { "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } }
    ]
}
```
</details>

---

## 🔗 Похожие проекты
- [vk-turn-proxy-android](https://github.com/MYSOREZ/vk-turn-proxy-android) - клиент для андроида
- [wireguard-turn-android](https://github.com/kiper292/wireguard-turn-android) - клиент для андроида интегрированный в WireGuard
- [WINGSV](https://github.com/WINGS-N/WINGSV) - клиент для андроида с One UI, WireGuard, раздачей VPN с root
- [turnbridge](https://github.com/nullcstring/turnbridge) - клиент для IOS
- [turn-proxy](https://github.com/Urtyom-Alyanov/turn-proxy) - реализация на Rust
- [lionheart](https://github.com/jaykaiperson/lionheart) - аналог для https://stream.wb.ru (статья: https://habr.com/ru/articles/1017410/)
- [whitelist-bypass](https://github.com/kulikov0/whitelist-bypass) - проброс через медиасервер SFU ВК и Яндекс Телемоста

<div align="center">
  <sub>Основано на открытом исходном коде. Спасибо проекту <a href="https://github.com/KillTheCensorship/Turnel">Turnel</a> за часть кода. ❤️</sub>
</div>
