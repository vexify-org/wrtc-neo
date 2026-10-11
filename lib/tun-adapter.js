// © Vexify 2026 All Rights Reserved.
const net = require('net');
const dgram = require('dgram');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');

/**
 * TUN 适配器 — 虚拟网卡（自带驱动，零外部依赖）
 * 
 * 三种模式，自动降级：
 * 1. TUN 模式 — 使用 wintun.dll（包内自带），创建真实虚拟网卡
 * 2. TAP 模式 — 使用 node-tuntap（需 OpenVPN 驱动）
 * 3. 代理模式 — 纯用户态 TCP/UDP 端口转发
 *
 * Windows: 包内自带 wintun.dll + wintun.sys，wrtc-neo tun-install 一键安装
 * Linux: /dev/net/tun + ioctl
 */

// 尝试加载 ffiko（纯 JS FFI，无需 Koffi/编译依赖）
let ffiko = null;
try { ffiko = require('ffiko'); } catch (e) { /* 降级 */ }

class TunAdapter extends EventEmitter {
    constructor(options = {}) {
        super();
        this._subnet = options.subnet || '10.0.0';
        this._adapterName = options.adapterName || null; // 可自定义网卡名
        this._mode = 'none';
        this._handle = null;
        this._tcpServers = [];
        this._udpServers = [];
        this._peerRoutes = new Map();
        this._forwardPorts = new Map();
        this._mtu = options.mtu || 1400;
        this._state = 'closed';
        this._readBuf = Buffer.alloc(65536);
        this._pollTimer = null;
    }

    async start() {
        this._state = 'starting';

        // 尝试 ffiko + wintun（自带驱动，纯 JS）
        if (ffiko && os.platform() === 'win32') {
            const result = await this._tryWintun();
            if (result) {
                this._mode = 'tun';
                this._handle = result.handle;
                this._adapterName = result.name;
                this._state = 'running';
                this.emit('ready', { mode: 'tun', name: this._adapterName });
                this._pollLoop();
                return { mode: 'tun', name: this._adapterName };
            }
        }

        // 尝试 Linux TUN
        if (os.platform() === 'linux') {
            const result = await this._tryLinuxTun();
            if (result) {
                this._mode = 'tun';
                this._handle = result.handle;
                this._adapterName = result.name;
                this._state = 'running';
                this.emit('ready', { mode: 'tun', name: this._adapterName });
                this._pollLoop();
                return { mode: 'tun', name: this._adapterName };
            }
        }

        // 降级到代理模式
        this._mode = 'proxy';
        this._state = 'running';
        this.emit('ready', { mode: 'proxy' });
        return { mode: 'proxy' };
    }

    // ============================================================
    // Wintun 模式（包内自带 DLL，ffiko 调用）
    // ============================================================
    async _tryWintun() {
        try {
            // 查找 wintun.dll：优先包内 tun/ 目录，其次 System32
            const dllPaths = [
                path.join(__dirname, '..', 'tun', 'wintun.dll'),
                path.join(__dirname, '..', 'tun', 'amd64', 'wintun.dll'),
                path.join(process.cwd(), 'node_modules', 'wrtc-neo', 'tun', 'wintun.dll'),
                path.join(process.cwd(), 'node_modules', 'wrtc-neo', 'tun', 'amd64', 'wintun.dll'),
                'wintun.dll'
            ];

            let wintun = null;
            for (const dllPath of dllPaths) {
                try {
                    wintun = ffiko.load(dllPath);
                    break;
                } catch (e) { /* try next */ }
            }

            if (!wintun) return null;

            // 定义 wintun API
            const WINTUN_MAX_POOL = '256';
            const WINTUN_MIN_RING_CAPACITY = 0x20000;

            // ffiko 的 func() 直接返回可调用函数
            const WintunStartup = wintun.func('int WintunStartup()');
            const WintunShutdown = wintun.func('void WintunShutdown()');
            const WintunCreateAdapter = wintun.func('void *WintunCreateAdapter(const char *Name, const char *TunnelType, const char *RequestedGUID)');
            const WintunCloseAdapter = wintun.func('void WintunCloseAdapter(void *Adapter)');
            const WintunDeleteAdapter = wintun.func('void WintunDeleteAdapter(void *Adapter, bool ForceCloseSessions, void *RebootRequired)');
            const WintunGetAdapterLUID = wintun.func('void *WintunGetAdapterLUID(void *Adapter)');
            const WintunGetRunningDriverVersion = wintun.func('uint32_t WintunGetRunningDriverVersion()');
            const WintunSetAdapterName = wintun.func('int WintunSetAdapterName(void *Adapter, const char *Name)');
            const WintunSetAdapterAddress = wintun.func('int WintunSetAdapterAddress(void *Adapter, const char *Address, uint32_t Netmask)');
            const WintunAllocateSendPacket = wintun.func('void *WintunAllocateSendPacket(void *Session, uint32_t PacketSize)');
            const WintunSendPacket = wintun.func('void WintunSendPacket(void *Session, void *Packet)');
            const WintunReceivePacket = wintun.func('int WintunReceivePacket(void *Session, void **Packet, uint32_t *PacketSize)');
            const WintunReleaseReceivePacket = wintun.func('void WintunReleaseReceivePacket(void *Session, void *Packet)');
            const WintunStartSession = wintun.func('void *WintunStartSession(void *Adapter, uint32_t Capacity)');
            const WintunEndSession = wintun.func('void WintunEndSession(void *Session)');

            // 初始化 wintun
            WintunStartup();
            const version = WintunGetRunningDriverVersion();
            if (version === 0) {
                WintunShutdown();
                return null; // 驱动未安装，需要 wrtc-neo tun-install
            }

            // 创建适配器
            const adapterName = this._adapterName || 'wrtc-neo-TUN';
            const adapter = WintunCreateAdapter(adapterName, 'wrtc-neo', null);
            if (!adapter) {
                WintunShutdown();
                return null;
            }

            // 设置 IP 地址
            const ip = `${this._subnet}.1`;
            const ipParts = ip.split('.').map(Number);
            const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
            WintunSetAdapterAddress(adapter, ip, 0xFFFFFF00);

            // 启动会话
            const session = WintunStartSession(adapter, WINTUN_MIN_RING_CAPACITY);
            if (!session) {
                WintunCloseAdapter(adapter);
                WintunShutdown();
                return null;
            }

            return {
                handle: { wintun, adapter, session, WintunSendPacket, WintunReceivePacket, WintunReleaseReceivePacket, WintunAllocateSendPacket, WintunEndSession, WintunCloseAdapter, WintunShutdown },
                name: adapterName,
                type: 'wintun'
            };
        } catch (e) {
            return null;
        }
    }

    // 轮询读取 wintun 包
    _pollLoop() {
        if (this._state !== 'running') return;

        this._pollTimer = setInterval(() => {
            try {
                if (this._mode === 'tun' && this._handle && this._handle.wintun) {
                    this._readWintunPacket();
                } else if (this._mode === 'tun' && this._handle && this._handle.fd !== undefined) {
                    this._readLinuxTunPacket();
                }
            } catch (e) { /* ignore poll errors */ }
        }, 1);
    }

    _readWintunPacket() {
        const h = this._handle;
        const packetAddrBuf = Buffer.alloc(8);  // 存储 WintunReceivePacket 写出的包指针
        const sizeBuf = Buffer.alloc(4);        // 存储写出的包大小

        // ffiko 取 memcpy 从原始地址复制数据
        const memcpy = this._memcpy();

        while (h.WintunReceivePacket(h.session, packetAddrBuf, sizeBuf) === 0) {
            const packetAddr = packetAddrBuf.readBigUInt64LE(0);
            const size = sizeBuf.readUInt32LE(0);
            if (packetAddr && size > 0) {
                const data = Buffer.alloc(size);
                memcpy(data, packetAddr, size);
                this._processTapPacket(data);
            }
            h.WintunReleaseReceivePacket(h.session, packetAddr);
        }
    }

    // 通过 ffiko 获取 libc/msvcrt 的 memcpy，用于读写原始指针内存
    _memcpy() {
        if (this._memcpyFn) return this._memcpyFn;
        const libName = os.platform() === 'win32' ? 'msvcrt.dll' : 'libc.so.6';
        const lib = ffiko.load(libName);
        const memcpy = lib.func('void *memcpy(void *, const void *, size_t)');
        this._memcpyFn = memcpy;
        return memcpy;
    }

    _readLinuxTunPacket() {
        try {
            const fs = require('fs');
            const buf = Buffer.alloc(this._mtu + 14);
            const bytes = fs.readSync(this._handle.fd, buf, 0, buf.length, null);
            if (bytes > 0) {
                this._processTapPacket(buf.slice(0, bytes));
            }
        } catch (e) {
            if (e.code !== 'EAGAIN' && e.code !== 'EWOULDBLOCK') {
                this.emit('error', e);
            }
        }
    }

    // ============================================================
    // Linux TUN
    // ============================================================
    async _tryLinuxTun() {
        try {
            const fs = require('fs');
            const { execSync } = require('child_process');

            const tunFd = fs.openSync('/dev/net/tun', 'r+');
            const ifreq = Buffer.alloc(40);
            ifreq.write(this._adapterName || 'wrtc-neo-tun', 0, 12, 'ascii');
            ifreq.writeUInt16LE(0x0001, 16); // IFF_TUN

            if (ffiko) {
                const libc = ffiko.load('libc.so.6');
                const ioctl = libc.func('int ioctl(int, int, void *)');
                const TUNSETIFF = 0x400454ca;
                const ret = ioctl(tunFd, TUNSETIFF, ifreq);
                if (ret < 0) { fs.closeSync(tunFd); return null; }
            } else {
                fs.closeSync(tunFd);
                return null;
            }

            const ip = `${this._subnet}.1`;
            const tunName = this._adapterName || 'wrtc-neo-tun';
            execSync(`ip addr add ${ip}/24 dev ${tunName} 2>/dev/null`, { timeout: 5000 });
            execSync(`ip link set ${tunName} up 2>/dev/null`, { timeout: 5000 });
            return { handle: { fd: tunFd }, name: tunName, type: 'linux-tun' };
        } catch (e) {
            return null;
        }
    }

    // ============================================================
    // 处理 TUN 包（ARP + IPv4）
    // ============================================================
    _processTapPacket(buffer) {
        if (buffer.length < 14) return;

        const etherType = buffer.readUInt16BE(12);

        if (etherType === 0x0806) {
            this._handleArp(buffer);
        } else if (etherType === 0x0800) {
            this._handleIPv4(buffer);
        }
    }

    _handleArp(buffer) {
        if (buffer.length < 42) return;
        const op = buffer.readUInt16BE(20);
        if (op !== 1) return;

        const targetIP = [];
        for (let i = 38; i < 42; i++) targetIP.push(buffer.readUInt8(i));
        const targetIPStr = targetIP.join('.');

        const peer = this._peerRoutes.get(targetIPStr);
        if (!peer && targetIPStr !== `${this._subnet}.1`) return;

        const reply = Buffer.alloc(42);
        buffer.copy(reply, 0, 0, 42);
        buffer.copy(reply, 0, 32, 6);
        buffer.copy(reply, 6, 22, 6);
        reply.writeUInt16BE(0x0806, 12);
        reply.writeUInt16BE(2, 20);

        for (let i = 0; i < 4; i++) {
            reply.writeUInt8(parseInt(targetIPStr.split('.')[i]), 28 + i);
        }

        this._writeToTun(reply);
    }

    _handleIPv4(buffer) {
        if (buffer.length < 20) return;
        const dstIP = [];
        for (let i = 30; i < 34; i++) dstIP.push(buffer.readUInt8(i));
        const dstIPStr = dstIP.join('.');

        const peer = this._peerRoutes.get(dstIPStr);
        if (!peer) return;

        this.emit('ipPacket', { srcIP: this._readBufferIP(buffer, 26), dstIP: dstIPStr, data: buffer });
    }

    _writeToTun(buffer) {
        if (this._mode !== 'tun' || !this._handle) return;

        try {
            if (this._handle.type === 'wintun') {
                const h = this._handle;
                const packet = h.WintunAllocateSendPacket(h.session, buffer.length);
                if (packet) {
                    this._memcpy()(packet, buffer, buffer.length);
                    h.WintunSendPacket(h.session, packet);
                }
            } else if (this._handle.fd !== undefined) {
                require('fs').writeSync(this._handle.fd, buffer);
            }
        } catch (e) { /* ignore */ }
    }

    // ============================================================
    // 端口转发模式
    // ============================================================
    addPortForward(localPort, virtualIP, virtualPort, protocol = 'tcp') {
        const key = `${protocol}:${localPort}`;
        if (this._forwardPorts.has(key)) return;
        this._forwardPorts.set(key, { virtualIP, virtualPort, protocol });

        if (protocol === 'tcp') {
            this._startTcpProxy(localPort, virtualIP, virtualPort);
        } else {
            this._startUdpProxy(localPort, virtualIP, virtualPort);
        }
    }

    _startTcpProxy(localPort, virtualIP, virtualPort) {
        const server = net.createServer((clientSocket) => {
            const peer = this._peerRoutes.get(virtualIP);
            if (!peer) { clientSocket.destroy(); return; }

            const remote = new net.Socket();
            remote.connect(peer.port, peer.address, () => {
                clientSocket.pipe(remote);
                remote.pipe(clientSocket);
            });
            remote.on('error', () => clientSocket.destroy());
            clientSocket.on('error', () => remote.destroy());
        });

        server.listen(localPort, '127.0.0.1', () => {
            this._tcpServers.push(server);
            this.emit('proxyReady', { protocol: 'tcp', localPort, virtualIP, virtualPort });
        });
        server.on('error', (err) => this.emit('error', err));
    }

    _startUdpProxy(localPort, virtualIP, virtualPort) {
        const server = dgram.createSocket('udp4');
        const clients = new Map();

        server.on('message', (msg, rinfo) => {
            const peer = this._peerRoutes.get(virtualIP);
            if (!peer) return;

            const key = `${rinfo.address}:${rinfo.port}`;
            if (!clients.has(key)) {
                const sock = dgram.createSocket('udp4');
                sock.on('message', (reply) => server.send(reply, rinfo.port, rinfo.address));
                clients.set(key, sock);
            }
            clients.get(key).send(msg, peer.port, peer.address);
        });

        server.bind(localPort, '127.0.0.1', () => {
            this._udpServers.push(server);
            this.emit('proxyReady', { protocol: 'udp', localPort, virtualIP, virtualPort });
        });
    }

    // ============================================================
    // 路由管理
    // ============================================================
    addRoute(peerId, virtualIP, address, port) {
        this._peerRoutes.set(virtualIP, { peerId, address, port });
    }

    removeRoute(virtualIP) {
        this._peerRoutes.delete(virtualIP);
    }

    getRoutes() {
        return [...this._peerRoutes.entries()].map(([ip, info]) => ({ virtualIP: ip, ...info }));
    }

    // ============================================================
    // IPv4 包构造
    // ============================================================
    createEthernetFrame(srcMAC, dstMAC, ipPayload) {
        const frame = Buffer.alloc(14 + ipPayload.length);
        for (let i = 0; i < 6; i++) frame.writeUInt8(dstMAC[i] || 0, i);
        for (let i = 0; i < 6; i++) frame.writeUInt8(srcMAC[i] || 0, 6 + i);
        frame.writeUInt16BE(0x0800, 12);
        ipPayload.copy(frame, 14);
        return frame;
    }

    createIPv4Packet(srcIP, dstIP, protocol, payload) {
        const headerLen = 20;
        const totalLen = headerLen + payload.length;
        const packet = Buffer.alloc(totalLen);

        packet.writeUInt8(0x45, 0);
        packet.writeUInt8(0, 1);
        packet.writeUInt16BE(totalLen, 2);
        packet.writeUInt16BE(Math.floor(Math.random() * 65535), 4);
        packet.writeUInt16BE(0x4000, 6);
        packet.writeUInt8(64, 8);
        packet.writeUInt8(protocol, 9);
        packet.writeUInt16BE(0, 10);

        const srcParts = srcIP.split('.').map(Number);
        for (let i = 0; i < 4; i++) packet.writeUInt8(srcParts[i], 12 + i);

        const dstParts = dstIP.split('.').map(Number);
        for (let i = 0; i < 4; i++) packet.writeUInt8(dstParts[i], 16 + i);

        payload.copy(packet, 20);
        this._computeIPChecksum(packet);
        return packet;
    }

    _computeIPChecksum(packet) {
        let sum = 0;
        const ihl = (packet.readUInt8(0) & 0x0F) * 4;
        for (let i = 0; i < ihl; i += 2) {
            if (i === 10) continue;
            sum += packet.readUInt16BE(i);
        }
        while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
        packet.writeUInt16BE(~sum & 0xFFFF, 10);
    }

    _readBufferIP(buffer, offset) {
        return [buffer.readUInt8(offset), buffer.readUInt8(offset+1), buffer.readUInt8(offset+2), buffer.readUInt8(offset+3)].join('.');
    }

    // ============================================================
    // 停止
    // ============================================================
    stop() {
        this._state = 'closed';

        if (this._pollTimer) {
            clearInterval(this._pollTimer);
            this._pollTimer = null;
        }

        if (this._handle) {
            try {
                if (this._handle.type === 'wintun') {
                    const h = this._handle;
                    if (h.WintunEndSession) h.WintunEndSession(h.session);
                    if (h.WintunCloseAdapter) h.WintunCloseAdapter(h.adapter);
                    if (h.WintunShutdown) h.WintunShutdown();
                } else if (this._handle.fd !== undefined) {
                    require('fs').closeSync(this._handle.fd);
                }
            } catch (e) { /* ignore */ }
            this._handle = null;
        }

        for (const server of this._tcpServers) server.close();
        this._tcpServers = [];
        for (const server of this._udpServers) server.close();
        this._udpServers = [];
        this._peerRoutes.clear();
        this._forwardPorts.clear();
    }

    get mode() { return this._mode; }
    get state() { return this._state; }
}

module.exports = TunAdapter;