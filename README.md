# WRTC Neo

A general-purpose WebRTC implementation for Node.js. Pure JavaScript, no native
build step — drop-in for environments where `wrtc` / `node-webrtc` binaries are
not available.

WRTC Neo provides the standard WebRTC API surface (`RTCPeerConnection`,
`RTCDataChannel`, ...) plus a full toolbelt for P2P networking: ICE with
STUN/TURN, UDP hole punching, NAT detection, virtual LAN, TUN adapters,
topology/DHT and reliable messaging.

## Features

- WebRTC-compatible API (RTCPeerConnection, RTCDataChannel, RTCSessionDescription, RTCIceCandidate)
- ICE agent with host / server-reflexive / relay candidates (RFC 8445-style)
- Built-in STUN client (Cloudflare, Google and other public servers)
- TURN client with long-term credential auth (MESSAGE-INTEGRITY + FINGERPRINT, UDP/TCP)
- UDP hole punching for direct NAT traversal
- NAT type detection (full-cone, restricted, port-restricted, symmetric)
- IPv4 / IPv6 dual-stack support
- DTLS-style encryption layer (ECDHE P-256 + AES-128-GCM)
- Signaling client over WebSocket
- Virtual LAN (UDP) and OpenVPN-based LAN modes
- TUN adapter for virtual NICs (Windows wintun / Linux tun)
- Network topology helpers: mesh, star, relay, Kademlia-style DHT
- Connection pool with reconnect, quality metrics and message buffering
- No native build (optional `ffiko` only for TUN support)
- Modern ES6+ architecture, works with plain Node.js

## Installation

```bash
npm install wrtc-neo
```

## Quick Start

```javascript
const wrtc = require('wrtc-neo');

const pc = new wrtc.RTCPeerConnection({
    iceServers: [
        { urls: 'stun:stun.cloudflare.com:3478' },
        {
            urls: 'turn:turn.example.com:3478?transport=udp',
            username: 'user',
            credential: 'pass'
        }
    ]
});

const dc = pc.createDataChannel('my-channel');

dc.on('open', () => {
    dc.send('hello peer');
});
dc.on('message', (event) => {
    console.log('Received:', event.data);
});

const offer = await pc.createOffer();
await pc.setLocalDescription(offer);

pc.onicecandidate = (event) => {
    if (event.candidate) {
        // Send candidate to the remote peer via your signaling channel
    }
};
```

A complete signaling flow looks like:

1. Node A creates an offer: `createOffer()` → `setLocalDescription()` → send SDP
   + candidates to Node B.
2. Node B: `setRemoteDescription(offer)` → `createAnswer()` →
   `setLocalDescription(answer)` → send SDP + candidates back.
3. Both sides forward ICE candidates with `pc.addIceCandidate(candidate)` and
   the ICE agent negotiates connectivity automatically.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Application                          │
├─────────────────────────────────────────────────────────────┤
│  RTCPeerConnection ── RTCDataChannel ── ReliableChannel     │
│        │                   │                (ACK/NACK,       │
│        │                   │                 dedup, retry)   │
├────────┼───────────────────┼─────────────────────────────────┤
│        ▼                   ▼                                 │
│   IceManager ◄── RTCIceCandidate      DtlsHandshake         │
│   (gather → pair → check → select)   (ECDHE P-256 +        │
│        │                              AES-128-GCM)          │
│        ├── STUN client (RFC 5389)                           │
│        ├── TurnClient (RFC 5766 relay)                      │
│        └── HolePuncher (UDP hole punching)                  │
├─────────────────────────────────────────────────────────────┤
│  SignalingClient (WebSocket)   NatDetector                  │
│  ConnectionPool / ReconnectBuffer / ConnectionQuality       │
├─────────────────────────────────────────────────────────────┤
│  VirtualLAN ── TunAdapter / OvpnAdapter                     │
│  NetworkTopology (mesh/star/relay + Kademlia DHT)           │
├─────────────────────────────────────────────────────────────┤
│                     Node.js dgram / net / ws                │
└─────────────────────────────────────────────────────────────┘
```

Data path: an application message goes through `ReliableChannel` (chunking,
ACK/retransmit, dedup) on top of an `RTCDataChannel`, whose payload is
encrypted by the DTLS-style layer once ICE selects a working candidate pair.
`IceManager` drives candidate gathering and connectivity checks; when no
direct path exists, `TurnClient` allocates a relay, or `HolePuncher`
simultaneously sends packets to both peers' public addresses to open UDP
state in the intervening NATs.

## Connection State Diagram

```
                       setLocalDescription
  new ──────────────────────────────────────► connecting
   ▲                                              │
   │ close()                ICE pair succeeds +    │
   │                        DTLS completes         ▼
   │◄─────────────────────────────────────  connected
   │         close()              │               │
   │                              │ ICE fail /    │ ICE fail on
   │                              ▼ all pairs      ▼ failover pair
   └──────────────────────  disconnected / failed exhausted → failed
```

`pc.connectionState` transitions: `new → connecting → connected`, with
`disconnected` on transient packet loss, `failed` when every candidate pair
(including relay) fails connectivity checks, and back to `new` only via
`close()` + a fresh instance. `iceConnectionState` mirrors the ICE agent
(`checking → connected → completed`, or `disconnected` / `failed`).

## NAT Traversal: How It Works

1. **Discovery** — `NatDetector` sends STUN Binding requests to two different
   servers (and a port-changed variant) and compares the reflected
   `XOR-MAPPED-ADDRESS`. Identical mappings ⇒ cone family; differing mappings
   ⇒ symmetric. Whether a response arrives from the changed IP/port decides
   between `full-cone`, `restricted`, `port-restricted` and
   `symmetric-firewall`; no answer at all ⇒ `blocked`.
2. **Candidate gathering** — `IceManager` collects `host` candidates from all
   interfaces, `srflx` candidates via STUN, and `relay` candidates via TURN.
3. **Pairing & checks** — local × remote candidates are paired; each pair gets
   an RFC 8445 priority (computed with 64-bit BigInt to avoid overflow) and is
   sticker-scored against the peer. STUN binding checks run over each pair
   until one succeeds; the controlling agent then nominates it.
4. **Hole punching** — with no signalling-grade server, `HolePuncher` has both
   peers simultaneously fire packets at each other's `srflx` address, so each
   NAT learns an outbound mapping and lets the inbound packet through.
5. **Last resort** — `TurnClient` relays traffic when both NATs are symmetric
   or punching fails.

Tip: pair `NatDetector.quickDetect()` with `HolePuncher` — punching succeeds
almost always against cone NATs, while symmetric↔symmetric needs TURN.

## API Overview

### Core WebRTC

| Export | Description |
| ------ | ----------- |
| `RTCPeerConnection` | Peer connection management (offer/answer, ICE, data channels) |
| `RTCDataChannel` | Ordered/reliable data channel over UDP or TCP |
| `RTCSessionDescription` | SDP offer/answer description |
| `RTCIceCandidate` | ICE candidate with SDP parsing |
| `IceManager` | ICE agent: gathering, connectivity checks, pair selection |
| `SdpParser` | Parse / stringify / modify SDP |
| `DtlsHandshake`, `DtlsServer` | ECDHE key agreement, cert fingerprints, AES-GCM encryption |

### NAT Traversal

| Export | Description |
| ------ | ----------- |
| `IceServerDiscovery` | Discover and latency-test STUN/TURN servers |
| `DEFAULT_STUN_SERVERS` | Built-in public STUN server list |
| `DEFAULT_TURN_SERVERS` | Built-in public TURN servers (test credentials) |
| `TurnClient` | TURN allocate / permissions / channels over UDP & TCP |
| `NatDetector` | NAT type classification |
| `HolePuncher` | Classic UDP hole punching |

### Messaging & Connections

| Export | Description |
| ------ | ----------- |
| `ReliableChannel` | ACK-based reliable channel on top of a data channel |
| `MessageBuffer` | Chunked byte queue |
| `ConnectionPool` | Keyed connection pool with auto-reconnect |
| `ConnectionQuality` | Latency / loss / jitter / score tracking |
| `ReconnectBuffer` | Offline message buffering with drain |
| `ConnectionStats` | Per-connection stats: throughput, rates, candidates |
| `SignalingClient` | WebSocket signaling with offer/answer/ICE envelope |

### Networking / LAN

| Export | Description |
| ------ | ----------- |
| `VirtualLAN` | Virtual subnet over UDP or OpenVPN |
| `TunAdapter` | Virtual NIC (Windows wintun, Linux tun) |
| `OvpnAdapter` | OpenVPN server/client wrapper |
| `NetworkTopology` | Mesh / star / relay topologies |
| `NodeId`, `RoutingTable` | Kademlia-style addressing and routing |
| `MediaStream`, `MediaStreamTrack`, `MediaRecorder` | Media abstractions |

## Examples

### Two peers over a signaling server

```javascript
const wrtc = require('wrtc-neo');

const signal = new wrtc.SignalingClient('ws://your-signaling-server:8080');
await signal.connect();

// A: initiator
const pcA = new wrtc.RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }] });
const dcA = pcA.createDataChannel('chat');
dcA.on('open', () => dcA.send('hi'));

const offer = await pcA.createOffer();
await pcA.setLocalDescription(offer);
signal.sendOffer('peer-b', offer);

pcA.onicecandidate = (e) => e.candidate && signal.sendIceCandidate('peer-b', e.candidate);
signal.on('message', async (msg) => {
    if (msg.type === 'answer') await pcA.setRemoteDescription(msg.answer);
    if (msg.type === 'ice_candidate') await pcA.addIceCandidate(msg.candidate);
});

// B: answerer
const pcB = new wrtc.RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }] });
pcB.ondatachannel = (event) => {
    const dcB = event.channel;
    dcB.on('message', (e) => console.log('B received:', e.data));
};
signal.on('message', async (msg) => {
    if (msg.type === 'offer') {
        await pcB.setRemoteDescription(msg.offer);
        const answer = await pcB.createAnswer();
        await pcB.setLocalDescription(answer);
        signal.sendAnswer('peer-a', answer);
    }
    if (msg.type === 'ice_candidate') await pcB.addIceCandidate(msg.candidate);
});
```

### UDP hole punching

```javascript
const puncher = new wrtc.HolePuncher();
await puncher.start(0);

const { address, port } = await puncher.discoverPublicAddress('stun.cloudflare.com', 3478);
puncher.punch('203.0.113.5', 40000, 'peer-id');
```

### Virtual LAN

```javascript
const lan = new wrtc.VirtualLAN({ networkId: 'my-room', subnet: '10.8.0' });
await lan.start('node-a', { localIP: '10.8.0.2' });

lan.onPacket((packet) => console.log('packet:', packet));
lan.sendPacket('10.8.0.3', Buffer.from('hello'));
```

### Reliable messaging

```javascript
const channel = pc.createDataChannel('reliable');
const reliable = new wrtc.ReliableChannel(channel, { maxRetries: 5 });
reliable.on('message', (msg) => console.log(msg.data));
await reliable.send({ hello: 'world' });
```

## Network Details

- **ICE**: host candidates from local interfaces, server-reflexive from STUN,
  relay from TURN, with priority-based connectivity checks.
- **STUN**: RFC 5389 binding requests/responses, XOR-MAPPED-ADDRESS decoding.
- **TURN**: RFC 5766 allocate/refresh/create-permission/channel-bind over UDP
  and TCP, long-term credential auth with nonce handling.
- **DTLS layer**: ECDHE P-256 key agreement with SHA-256 PRF and AES-128-GCM
  payload encryption, certificate fingerprint exchange via SDP.
- **Data channels**: custom UDP/TCP framing (not SCTP). `ReliableChannel`
  provides ACK-based reliability on top.

## Requirements

- Node.js >= 16
- For the TUN adapter, [ffiko](https://www.npmjs.com/package/ffiko) is
  required (optional dependency) and, on Windows, the wintun driver
  (`tun/install.bat`).

## Testing

```bash
npm test
```

The suite is fully offline — every network dependency (STUN, WebSocket
signaling) is mocked with local UDP/WS servers, so tests are deterministic and
run in seconds:

| Suite | Covers |
| ----- | ------ |
| `test/basic.test.js` | SDP, data channel, offer/answer smoke tests |
| `test/stun-vector.test.js` | RFC 5389/5769 message vectors, XOR-MAPPED-ADDRESS |
| `test/ice.test.js` | candidate parsing, BigInt pair priority, SDP attribute dedup |
| `test/reliable-channel.test.js` | ACK, retry, dedup bound, buffer eviction |
| `test/hole-puncher.test.js` | bind conflicts, punch handshake, listener cleanup |
| `test/nat.test.js` | full NAT classification matrix vs mock STUN |
| `test/signaling.test.js` | reconnect, duplicate-socket guard, heartbeat |
| `test/connection-pool.test.js` | timer leaks, intentional-close vs drop semantics |

## License

Apache-2.0 - Copyright (c) Vexify 2026