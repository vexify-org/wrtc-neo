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
        this.socket = dgram.createSocket('udp4');
        this.socket.on('message', (msg, rinfo) => {
            this._handlePacket(msg, rinfo);
        });

        return new Promise((resolve, reject) => {
            this.socket.bind(options.port || 0, () => {
                this.state = 'running';
                const port = this.socket.address().port;
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

    addPeer(peerId, virtualIP, address, port) {
        this.peers.set(virtualIP, { peerId, address, port });
        console.log(`[VirtualLAN] Peer added: ${virtualIP} -> ${peerId} (${address}:${port})`);
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

        const peer = this.peers.get(targetIP);
        if (!peer) {
            console.error(`[VirtualLAN] Unknown target: ${targetIP}`);
            return false;
        }

        const packet = this._createPacket(this.localIP, targetIP, data);
        this.socket.send(packet, peer.port, peer.address);
        return true;
    }

    broadcast(data) {
        if (this._ovpnMode) {
            // OVPN 模式下广播由 OpenVPN 处理
            return;
        }

        const packet = this._createPacket(this.localIP, `${this.subnet}.255`, data);
        for (const [ip, peer] of this.peers.entries()) {
            this.socket.send(packet, peer.port, peer.address);
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
        const payload = buffer.slice(11, 11 + payloadLen);
        return { srcIP, dstIP, payload };
    }

    _handlePacket(msg, rinfo) {
        const packet = this._parsePacket(msg);
        if (!packet) return;

        if (packet.dstIP !== this.localIP && packet.dstIP !== `${this.subnet}.255`) {
            return;
        }

        for (const handler of this.packetHandlers) {
            handler(packet, rinfo);
        }
    }

    onPacket(handler) {
        this.packetHandlers.push(handler);
    }

    // ============================================================
    // IP 编解码
    // ============================================================
    _writeIP(buffer, offset, ip) {
        const parts = ip.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            buffer.writeUInt8(parts[i] || 0, offset + i);
        }
    }

    _readIP(buffer, offset) {
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
            this.socket.close();
            this.socket = null;
        }

        this.state = 'closed';
        this._ovpnMode = false;
    }
}

module.exports = VirtualLAN;