// © Vexify 2026 All Rights Reserved.
const dgram = require('dgram');
const OvpnAdapter = require('./ovpn-adapter');

/**
 * 虚拟局域网 (VPN) 实现
 * 支持 OVPN 模式（OpenVPN TAP 真实虚拟网卡）和 UDP 端口转发模式
 */
class VirtualLAN {
    constructor(options = {}) {
        this.networkId = options.networkId || 'wrtc-neo';
        this.subnet = options.subnet || '10.0.0';
        this.netmask = options.netmask || '255.255.255.0';
        this.mtu = options.mtu || 1400;

        this.peers = new Map();  // virtualIP -> { peerId, address, port }
        this.ipPool = new Set();
        this.localIP = null;
        this.localPeerId = null;
        this.socket = null;
        this.state = 'closed';
        this.packetHandlers = [];
        this._ovpn = null;
        this._ovpnMode = false;
        this._allowUnknownSources = options.allowUnknownSources === true;
        this._maxPeers = Number.isInteger(options.maxPeers) && options.maxPeers > 0
            ? Math.min(options.maxPeers, 1024) : 512;

        // 预分配 IP 池
        for (let i = 2; i < 255; i++) {
            this.ipPool.add(`${this.subnet}.${i}`);
        }
        // 10.0.0.1 保留给 OVPN 服务器
    }

    // ============================================================
    // 启动
    // ============================================================
    /**
     * 启动虚拟局域网
     * @param {string} localPeerId
     * @param {object} options
     * @param {boolean} options.ovpn - 是否启用 OVPN 模式（真实虚拟网卡，需要 OpenVPN）
     * @param {number} options.port - OVPN 端口
     * @param {boolean} options.server - 是否作为 OVPN 服务器
     * @param {string} options.serverHost - OVPN 客户端模式下的服务器地址
     * @param {number} options.serverPort - OVPN 客户端模式下的服务器端口
     * @param {string} options.staticKey - OVPN 静态密钥
     */
    async start(localPeerId, options = {}) {
        if (typeof localPeerId !== 'string' || !localPeerId || localPeerId.length > 256) {
            throw new TypeError('Invalid localPeerId');
        }
        if (this.state === 'running') {
            throw new Error('VirtualLAN already started');
        }
        this.localPeerId = localPeerId;
        this.localIP = await this.allocateIP(localPeerId);

        // 尝试 OVPN 模式
        if (options.ovpn !== false && OvpnAdapter.isInstalled()) {
            try {
                this._ovpn = new OvpnAdapter({
                    subnet: this.subnet,
                    port: options.port || 1194
                });

                // 设置静态密钥
                if (options.staticKey) {
                    this._ovpn.setStaticKey(options.staticKey);
                }

                this._ovpn.on('log', (entry) => {
                    console.log(`[OVPN] ${entry.text}`);
                });

                if (options.server) {
                    // 主机模式
                    const result = await this._ovpn.startServer();
                    this._ovpnMode = true;
                    this.localIP = result.ip;
                    this.state = 'running';
                    console.log(`[VirtualLAN] OVPN server started on ${result.ip}:${result.port}`);
                    return { ip: this.localIP, port: result.port, mode: 'ovpn' };
                } else if (options.serverHost && options.serverPort) {
                    // 客户端模式
                    const result = await this._ovpn.startClient(
                        options.serverHost,
                        options.serverPort,
                        options.localIP || this.localIP
                    );
                    this._ovpnMode = true;
                    this.localIP = result.ip;
                    this.state = 'running';
                    console.log(`[VirtualLAN] OVPN client connected to ${options.serverHost}:${options.serverPort}, IP: ${this.localIP}`);
                    return { ip: this.localIP, mode: 'ovpn', server: `${options.serverHost}:${options.serverPort}` };
                }
            } catch (e) {
                console.log(`[VirtualLAN] OVPN not available: ${e.message}, using UDP mode`);
                this._ovpn = null;
                this._ovpnMode = false;
            }
        } else if (options.ovpn !== false && !OvpnAdapter.isInstalled()) {
            console.log(`[VirtualLAN] OpenVPN not installed, using UDP mode`);
        }

        // UDP 回退模式
        const bindPort = options.port === undefined ? 0 : options.port;
        if (!Number.isInteger(bindPort) || bindPort < 0 || bindPort > 65535) {
            throw new RangeError(`Invalid port: ${options.port}`);
        }

        const socket = dgram.createSocket('udp4');
        this.socket = socket;
        socket.on('message', (msg, rinfo) => {
            this._handlePacket(msg, rinfo);
        });

        return new Promise((resolve, reject) => {
            let settled = false;
            const fail = (err) => {
                if (settled) return;
                settled = true;
                if (this.socket === socket) this.socket = null;
                try { socket.close(); } catch (e) { /* ignore */ }
                this.state = 'closed';
                reject(err);
            };

            // 缺少 error 监听会让 bind 失败变成未捕获 'error' 事件并终止进程
            socket.once('error', fail);
            socket.bind(bindPort, () => {
                if (settled) return;
                settled = true;
                socket.removeListener('error', fail);
                socket.on('error', (err) => {
                    console.error('[VirtualLAN] Socket error:', err.message);
                });
                this.state = 'running';
                const port = socket.address().port;
                console.log(`[VirtualLAN] Started on port ${port}, local IP: ${this.localIP}, mode: UDP`);
                resolve({ ip: this.localIP, port, mode: 'udp' });
            });
        });
    }

    // ============================================================
    // IP 管理
    // ============================================================
    async allocateIP(peerId) {
        const existing = [...this.peers.entries()].find(([, v]) => v.peerId === peerId);
        if (existing) return existing[0];

        for (const ip of this.ipPool) {
            if (!this.peers.has(ip)) {
                this.ipPool.delete(ip);
                return ip;
            }
        }

        throw new Error('No available IP in pool');
    }

    /** 校验 IPv4 是否属于本 VLAN 子网 */
    _isSubnetIP(ip) {
        if (typeof ip !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
        const parts = ip.split('.').map(Number);
        if (parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return false;
        const prefix = this.subnet.split('.').map(Number);
        if (prefix.length !== 3 || prefix.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return false;
        return parts[0] === prefix[0] && parts[1] === prefix[1] && parts[2] === prefix[2];
    }

    addPeer(peerId, virtualIP, address, port) {
        if (typeof peerId !== 'string' || !peerId || peerId.length > 256) {
            throw new TypeError('Invalid peerId');
        }
        if (!this._isSubnetIP(virtualIP)) {
            throw new RangeError(`virtualIP ${virtualIP} is not in subnet ${this.subnet}.0/24`);
        }
        if (typeof address !== 'string' || !address || address.length > 255) {
            throw new TypeError('Invalid peer address');
        }
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            throw new RangeError(`Invalid peer port: ${port}`);
        }
        if (!this.peers.has(virtualIP) && this.peers.size >= this._maxPeers) {
            throw new Error('Peer table full');
        }
        this.peers.set(virtualIP, { peerId, address, port });
        this.ipPool.delete(virtualIP);
        console.log(`[VirtualLAN] Peer added: ${virtualIP} -> ${peerId} (${address}:${port})`);
    }

    /**
     * 移除对端并释放虚拟 IP（旧实现只分配不回收，IP 池会被永久耗尽）
     */
    removePeer(virtualIP) {
        if (!this.peers.has(virtualIP)) return false;
        this.peers.delete(virtualIP);
        if (virtualIP !== this.localIP && this._isSubnetIP(virtualIP)) {
            this.ipPool.add(virtualIP);
        }
        return true;
    }

    getPeerByIP(virtualIP) {
        return this.peers.get(virtualIP);
    }

    getPeerByPeerId(peerId) {
        for (const [ip, info] of this.peers.entries()) {
            if (info.peerId === peerId) return { virtualIP: ip, ...info };
        }
        return null;
    }

    // ============================================================
    // 数据包
    // ============================================================
    sendPacket(targetIP, data) {
        if (this._ovpnMode) {
            // OVPN 模式下，OpenVPN 已经处理了所有路由
            // 不需要手动发送
            return true;
        }

        if (!this.socket || this.state !== 'running') {
            console.error('[VirtualLAN] Not running');
            return false;
        }

        const peer = this.peers.get(targetIP);
        if (!peer) {
            console.error(`[VirtualLAN] Unknown target: ${targetIP}`);
            return false;
        }

        const packet = this._createPacket(this.localIP, targetIP, data);
        try {
            this.socket.send(packet, peer.port, peer.address);
        } catch (e) {
            console.error(`[VirtualLAN] send failed: ${e.message}`);
            return false;
        }
        return true;
    }

    broadcast(data) {
        if (this._ovpnMode) {
            // OVPN 模式下广播由 OpenVPN 处理
            return;
        }

        if (!this.socket || this.state !== 'running') return;
        const packet = this._createPacket(this.localIP, `${this.subnet}.255`, data);
        for (const [, peer] of this.peers.entries()) {
            try {
                this.socket.send(packet, peer.port, peer.address);
            } catch (e) {
                console.error(`[VirtualLAN] broadcast send failed: ${e.message}`);
            }
        }
    }

    // ============================================================
    // OVPN 相关
    // ============================================================
    get ovpnAdapter() {
        return this._ovpn;
    }

    get isOvpnMode() {
        return this._ovpnMode;
    }

    /**
     * 获取 OVPN 静态密钥（供客户端使用）
     */
    getStaticKey() {
        return this._ovpn ? this._ovpn.getStaticKey() : null;
    }

    /**
     * 设置 OVPN 静态密钥（客户端使用）
     */
    setStaticKey(key) {
        if (this._ovpn) {
            this._ovpn.setStaticKey(key);
        }
    }

    // ============================================================
    // 包处理（UDP 模式）
    // ============================================================
    _createPacket(srcIP, dstIP, payload) {
        const payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
        if (payloadBuf.length > 0xFFFF - 11) {
            throw new RangeError('payload too large for VLAN packet');
        }
        if (!this._isSubnetIP(srcIP) && srcIP !== `${this.subnet}.255`) {
            throw new RangeError(`Invalid source IP: ${srcIP}`);
        }
        if (!this._isSubnetIP(dstIP) && dstIP !== `${this.subnet}.255`) {
            throw new RangeError(`Invalid destination IP: ${dstIP}`);
        }
        const packet = Buffer.alloc(11 + payloadBuf.length);
        packet.writeUInt8(1, 0);
        this._writeIP(packet, 1, srcIP);
        this._writeIP(packet, 5, dstIP);
        packet.writeUInt16BE(payloadBuf.length, 9);
        payloadBuf.copy(packet, 11);
        return packet;
    }

    _parsePacket(buffer) {
        if (buffer.length < 11) return null;
        const version = buffer.readUInt8(0);
        if (version !== 1) return null;
        const srcIP = this._readIP(buffer, 1);
        const dstIP = this._readIP(buffer, 5);
        const payloadLen = buffer.readUInt16BE(9);
        // 声明长度超过实际包长 → 畸形包，直接丢弃（slice 会静默截断）
        if (payloadLen > buffer.length - 11) return null;
        const payload = buffer.slice(11, 11 + payloadLen);
        return { srcIP, dstIP, payload };
    }

    _handlePacket(msg, rinfo) {
        if (!Buffer.isBuffer(msg) || msg.length < 11 || msg.length > 65535) return;
        const packet = this._parsePacket(msg);
        if (!packet) return;

        if (packet.dstIP !== this.localIP && packet.dstIP !== `${this.subnet}.255`) {
            return;
        }

        // 防伪造：源虚拟 IP 必须是已登记的对端，且（若已知）源地址需匹配
        if (!this._allowUnknownSources) {
            const sender = this.peers.get(packet.srcIP);
            if (!sender) return;
            if (rinfo && typeof rinfo.address === 'string' && sender.address && rinfo.address !== sender.address) {
                return;
            }
        }

        for (const handler of this.packetHandlers) {
            try {
                handler(packet, rinfo);
            } catch (e) {
                console.error('[VirtualLAN] packet handler error:', e.message);
            }
        }
    }

    onPacket(handler) {
        if (typeof handler !== 'function') throw new TypeError('handler must be a function');
        this.packetHandlers.push(handler);
    }

    // ============================================================
    // IP 编解码
    // ============================================================
    _writeIP(buffer, offset, ip) {
        if (typeof ip !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
            throw new TypeError(`Invalid IPv4 address: ${ip}`);
        }
        const parts = ip.split('.').map(Number);
        if (parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) {
            throw new RangeError(`Invalid IPv4 address: ${ip}`);
        }
        for (let i = 0; i < 4; i++) {
            buffer.writeUInt8(parts[i], offset + i);
        }
    }

    _readIP(buffer, offset) {
        if (offset + 4 > buffer.length) return '0.0.0.0';
        const parts = [];
        for (let i = 0; i < 4; i++) {
            parts.push(buffer.readUInt8(offset + i));
        }
        return parts.join('.');
    }

    // ============================================================
    // 状态
    // ============================================================
    getStatus() {
        return {
            networkId: this.networkId,
            subnet: this.subnet,
            localIP: this.localIP,
            peerCount: this.peers.size,
            state: this.state,
            ovpnMode: this._ovpnMode,
            mode: this._ovpnMode ? 'OVPN' : 'UDP',
            ovpn: this._ovpn ? this._ovpn.getStatus() : null
        };
    }

    listPeers() {
        const result = [];
        for (const [ip, info] of this.peers.entries()) {
            result.push({
                virtualIP: ip,
                peerId: info.peerId,
                address: info.address,
                port: info.port
            });
        }
        return result;
    }

    stop() {
        if (this._ovpn) {
            this._ovpn.stop();
            this._ovpn = null;
        }

        if (this.socket) {
            try { this.socket.close(); } catch (e) { /* ignore */ }
            this.socket = null;
        }

        this.state = 'closed';
        this._ovpnMode = false;
        this.packetHandlers = [];
    }
}

module.exports = VirtualLAN;