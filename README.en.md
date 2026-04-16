# VK/WB TURN Proxy
[Russian version](README.md)

Tunnels WireGuard/Hysteria traffic through VK Calls or WB Stream TURN servers. Packets are encrypted with DTLS 1.2 and then sent in parallel streams via TCP or UDP to the TURN server using the STUN ChannelData protocol. From there, they are forwarded via UDP to your server, decrypted, and passed to WireGuard. TURN credentials are generated from the meeting link.

## Features

- **VK Calls** — TURN credentials from VK API with automatic captcha solving (Not Robot)
- **WB Stream** — TURN credentials from WB Stream API (LiveKit ICE)
- **Caching** — 10 minute TTL with shared cache across 4 streams
- **DTLS obfuscation** — DPI bypass via DTLS tunnel
- **Multiple connections** — up to N parallel connections to TURN

**Update: Multi-user Proxy Server**
The current implementation supports multiple simultaneous users through a single proxy server.
- **Session Identification:** The client generates a unique 16-byte UUID at startup.
- **Stream Aggregation:** The server groups all incoming DTLS connections from a single client by its UUID.
- **Stable Backend:** For each session, exactly one UDP connection is created to the WireGuard server. This prevents the "endpoint thrashing" issue and increases stability.
- **Load Balancing:** Outgoing traffic from the server to the client is distributed among all active DTLS streams of the user (Round-Robin).

For educational purposes only!

## Client Structure

```
client/
├── credentials.go    # Shared credentials cache, request serialization
├── vk.go             # VK API: Token 1→4 chain, HTTP requests
├── vk_captcha.go     # VK Captcha: PoW solving, Not Robot flow
├── wb.go             # WB Stream: guest register → room → LiveKit ICE
└── main.go           # DTLS/TURN connections, CLI, main loop
```

## Setup

You will need:
1. A link to an active VK call: create your own (requires a VK account) or search for `"https://vk.com/call/join/"`. Links are valid forever unless "end call for all" is clicked.
2. A VPS with WireGuard installed.
3. For Android: Download Termux from F-Droid.

### Server

```bash
./server -listen 0.0.0.0:56000 -connect 127.0.0.1:<wg_port>
```

### Client

#### Android

**Recommended method:**
Use the native Android app [wireguard-turn-android](https://github.com/kiper292/wireguard-turn-android). This is a modified WireGuard client with built-in TURN support.

**Alternative method (via Termux):**
- In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.
- **Add Termux to WireGuard exceptions. Click "Save".**

In Termux:
```bash
termux-wake-lock
```
The phone will not enter deep sleep. To disable:
```bash
termux-wake-unlock
```
Copy the binary to a local folder and grant execution rights:
```bash
cp /sdcard/Download/client-android ./
chmod 777 ./client-android
```

**VK mode:**
```bash
./client-android -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000
```

**WB mode:**
```bash
./client-android -wb -peer <wg_server_ip>:56000 -listen 127.0.0.1:9000
```

Additional flags:
- `-session-id <hex>`: set a fixed session ID (32 hex characters).
- `-n <num>`: number of connections to TURN (default 4).
- `-udp`: use UDP for TURN (default TCP).
- `-turn <ip>`: override TURN server address.
- `-port <port>`: override TURN server port.
- `-no-dtls`: without DTLS obfuscation (may result in a ban).
- `-v1`: use v1 protocol (no session_id and stream_id sent). For legacy servers.

#### Linux

In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.

The script will add routes to the necessary IPs:

```bash
./client-linux -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000 | sudo routes.sh
```

```bash
./client-linux -wb -peer <wg_server_ip>:56000 -listen 127.0.0.1:9000 | sudo routes.sh
```

⚠️ Do not enable the VPN until the program has established a connection! Unlike Android, some requests will go through the VPN here (DNS and TURN connection requests).

#### Windows

In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.

In PowerShell as Administrator (so the script can add routes):

```powershell
./client.exe -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000 | routes.ps1
```

```powershell
./client.exe -wb -peer <wg_server_ip>:56000 -listen 127.0.0.1:9000 | routes.ps1
```

⚠️ Do not enable the VPN until the program has established a connection! Unlike Android, some requests will go through the VPN here (DNS and TURN connection requests).

### If it doesn't work

Use the `-turn` option to manually specify a TURN server address. This should be a VK, Max, or Odnoklassniki server (VK link) or WB Stream (WB mode).

If TCP doesn't work, try adding the `-udp` flag.

Add `-n 1` for a more stable single-stream connection (limited to 5 Mbps for VK).

## VK Auth Flow

1. **Token 1** — anonymous token (`login.vk.ru`)
2. **getCallPreview** — call preview (optional)
3. **Token 2** — anonymous token for the call (`api.vk.ru`)
   - On captcha → PoW solving → retry
4. **Token 3** — OK session key (`calls.okcdn.ru`)
5. **Token 4** — TURN credentials (`calls.okcdn.ru`)

## WB Auth Flow

1. **Guest register** — guest registration (`stream.wb.ru`)
2. **Create room** — create a room
3. **Join room** — join the room
4. **Get token** — get roomToken
5. **LiveKit ICE** — WebSocket to LiveKit, protobuf TURN parsing

## Caching

- TTL: **10 minutes** (safety margin 60 seconds)
- One cache per **4 streams** (`streamID / 4`)
- Fast path via `RLock`
- Fetch serialization via global `fetchMu`

## v2ray

Instead of WireGuard, you can use any V2Ray core that supports it (e.g., xray or sing-box) and any V2Ray client that uses this core (e.g., v2rayN or v2rayNG). This allows you to add more inbound interfaces (e.g., SOCKS) and implement fine-grained routing.

Example configs:

<details>

<summary>
Client
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
Server
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

With the `-no-dtls` flag, you can send packets without DTLS obfuscation and connect to regular WireGuard servers. This may result in a ban from VK/WB.

Thanks to https://github.com/KillTheCensorship/Turnel for part of the code :)

WB Stream functionality is based on https://github.com/jaykaiperson/lionheart
