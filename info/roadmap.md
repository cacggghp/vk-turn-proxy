# Roadmap: Multi-User DTLS Proxy for WireGuard

## 1. Objective
Transform the current simple one-to-one DTLS proxy into a multi-user, session-aware proxy server. This will allow the server to multiplex multiple DTLS streams from a single client into a single stable backend connection to the WireGuard server, solving the "endpoint thrashing" issue and enabling proper multi-client support.

## 2. Current Implementation Analysis
### Architecture
*   **Client:** Opens $N$ parallel DTLS connections to the server. Forwards WireGuard packets from a local UDP socket to these connections round-robin.
*   **Server:** Listens for DTLS connections. For *each* incoming connection, it dials a *new, independent* UDP connection to the WireGuard backend.
*   **Data Flow:** `Client (1 UDP) -> [N DTLS Conns] -> Server -> [N UDP Conns] -> WireGuard Server`

### Downsides
1.  **Endpoint Thrashing:** The WireGuard server sees packets from the same peer coming from $N$ different source ports (the $N$ backend UDP connections). This causes WireGuard to constantly update the peer's endpoint, leading to packet loss and performance degradation.
2.  **No User Identification:** The server has no way to group connections. It treats every DTLS handshake as a stranger.
3.  **Resource Waste:** 16 client streams result in 16 server-side sockets and goroutines.
4.  **Scalability:** Cannot differentiate between Client A and Client B if they share an IP or just purely based on logic.

## 3. Target Architecture (from TODO.txt)
### Concept
*   **Session ID:** Clients generate a unique ID (UUID) and send it as the first packet after the DTLS handshake.
*   **Session Aggregation:** The server maintains a `Session` object for each ID, containing a list of active DTLS streams and *one* shared backend UDP connection.
*   **Data Flow:** `Client (1 UDP) -> [N DTLS Conns] -> Server (Aggregator) -> [1 UDP Conn] -> WireGuard Server`

## 4. Implementation Roadmap

### Phase 1: Protocol Definition
Define a simple handshake protocol.
*   **Handshake:** Immediately after the DTLS handshake completes, the Client sends a fixed-length packet containing the Session ID.
    *   Format: Raw bytes of the UUID (16 bytes).
    *   Constraint: WireGuard packets (Types 1-4) are distinguishable, but strict ordering ("First packet is ID") is simpler and robust for this use case.

### Phase 2: Server Refactoring (`server/main.go`)
1.  **Data Structures:**
    ```go
    type UserSession struct {
        ID          string
        Conns       []*dtls.Conn // Active DTLS streams
        BackendConn *net.UDPConn // Shared connection to WG server
        Lock        sync.RWMutex
    }
    type SessionManager struct {
        Sessions map[string]*UserSession
        Lock     sync.RWMutex
    }
    ```
2.  **Connection Handling Logic:**
    *   Accept DTLS connection.
    *   Perform DTLS Handshake.
    *   **Read First Packet:** Expect 16 bytes (UUID).
    *   **Session Lookup:**
        *   If ID exists: Add new DTLS conn to `UserSession.Conns`.
        *   If ID is new: Create `UserSession`, dial `BackendConn`, start backend reader loop.
3.  **Forwarding Logic (Upstream):**
    *   Read from any DTLS conn in `UserSession`.
    *   Write to `UserSession.BackendConn`.
4.  **Forwarding Logic (Downstream):**
    *   Read from `UserSession.BackendConn`.
    *   Select a DTLS conn from `UserSession.Conns` (Round-Robin or Random).
    *   Write packet.
5.  **Cleanup:**
    *   Handle DTLS disconnection: Remove from `UserSession.Conns`.
    *   If `UserSession.Conns` is empty for timeout period: Close `BackendConn` and remove Session.

### Phase 3: Client Refactoring (`client/main.go`)
1.  **Session ID Generation:**
    *   Generate a UUID at startup (or accept via flag `-session-id` for persistence).
2.  **Handshake Implementation:**
    *   In `oneDtlsConnection`, after `dtlsConn.HandshakeContext` success:
    *   Write the UUID to `dtlsConn`.
3.  **Logic Update:**
    *   Ensure the client continues to use the pool of connections as before.

### Phase 4: Robustness & Optimization
1.  **Keep-Alives:**
    *   Ensure the client sends periodic traffic (or dummy packets) if the tunnel is idle, to keep the NAT mappings alive for all $N$ streams.
    *   WireGuard sends keep-alives, which helps, but we might need application-level pings if we want to keep *all* streams active and not just the one currently carrying traffic.
2.  **Locking:**
    *   Properly implement `RWMutex` on the SessionManager to handle concurrent adds/removes.
3.  **Zombie Cleanup:**
    *   Implement timeouts. If a session has no active DTLS connections, close the backend socket.

## 5. Verification Plan
1.  **Unit/Integration Test:**
    *   Start a dummy UDP server (simulating WG).
    *   Start Proxy Server.
    *   Start Proxy Client with `n=2`.
    *   Client sends "Hello".
    *   Verify Dummy Server sees "Hello" from *one* IP:Port.
    *   Client sends "World" via second stream.
    *   Verify Dummy Server sees "World" from *same* IP:Port.
    *   Dummy Server replies.
    *   Verify Client receives reply.
