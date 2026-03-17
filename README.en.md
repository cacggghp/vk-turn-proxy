# Good TURN
[Russian version](README.md)

Tunnels WireGuard/Hysteria traffic through VK Calls or Yandex Telemost TURN servers. Packets are encrypted with DTLS 1.2 and then sent in parallel streams via TCP or UDP to the TURN server using the STUN ChannelData protocol. From there, they are forwarded via UDP to your server, decrypted, and passed to WireGuard. TURN credentials are generated from the meeting link.

**Update: Multi-user Proxy Server**
The current implementation supports multiple simultaneous users through a single proxy server.
- **Session Identification:** The client generates a unique 16-byte UUID at startup.
- **Stream Aggregation:** The server groups all incoming DTLS connections from a single client by its UUID.
- **Stable Backend:** For each session, exactly one UDP connection is created to the WireGuard server. This prevents the "endpoint thrashing" issue and increases stability.
- **Load Balancing:** Outgoing traffic from the server to the client is distributed among all active DTLS streams of the user (Round-Robin).

For educational purposes only!

## Setup
You will need:
1. A link to an active VK call: create your own (requires a VK account) or search for `"https://vk.com/call/join/"`. Links are valid forever unless "end call for all" is clicked.
2. Or a link to a Yandex Telemost call: `"https://telemost.yandex.ru/j/"`. Better not to search for these as conference participants are visible.
3. A VPS with WireGuard installed.
4. For Android: Download Termux from F-Droid.

### Server
```bash
./server -listen 0.0.0.0:56000 -connect 127.0.0.1:<wg_port>
```

### Client
#### Android

**Recommended method:**
Use the native Android app [vk-turn-proxy-android](https://github.com/MYSOREZ/vk-turn-proxy-android).
- In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.
- **Add the app to WireGuard exceptions (Excluded Applications). Click "Save".**

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
Run:
```bash
./client-android -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000
```
Additional flags:
- `-session-id <hex>`: set a fixed session ID (32 hex characters).

Or:
```bash
./client-android -udp -turn 5.255.211.241 -peer <wg_server_ip>:56000 -yandex-link <Ya_link> -listen 127.0.0.1:9000
```

#### Linux
In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.

The script will add routes to the necessary IPs:
```bash
./client-linux -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000 | sudo routes.sh
```

#### Windows
In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.

In PowerShell as Administrator (so the script can add routes):
```powershell
./client.exe -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000 | routes.ps1
```

### If it doesn't work
Use the `-turn` option to manually specify a TURN server address.
If TCP doesn't work, try adding the `-udp` flag.
Add `-n 1` for a more stable single-stream connection (limited to 5 Mbps for VK).

## Yandex Telemost
**UPD. TELEMOST IS CLOSED**
Unlike VK, Yandex servers do not limit speed, so the default is `-n 1`.

## Direct mode
With the `-no-dtls` flag, you can send packets without DTLS obfuscation and connect to regular WireGuard servers. This may result in a ban from VK/Yandex.
