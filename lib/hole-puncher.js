// © Vexify 2026 All Rights Reserved.
const dgram = require('dgram');
const crypto = require('crypto');
const net = require('net');

const MAX_CONTROL_MESSAGE = 4096;      // 控制消息上限（punch/ack）
const MAX_PEERS = 1024;                // 对端表上限，防止内存耗尽
const PUNCH_WINDOW_MS = 60000;         // punch 时间戳容忍窗口
const MAX_PUNCH_PER_SEC = 20;          // 每个源 IP 的 punch 速率上限
const MAX_PEER_ID_LEN = 256;
const MAX_DATA_LEN = 65507;            // UDP 最大负载

/**
 * 判断是否是内网/回环/链路本地地址。
 * 无共享密钥（legacy 模式）时只允许这些来源发起未认证 punch，
 * 避免成为公网反射放大（DDoS）的放大器。
 */
function isPrivateAddress(address) {
    if (typeof address !== 'string') return false;
    const family = net.isIP(address);
    if (family === 4) {
        const parts = address.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return false;
        const [a, b] = parts;
        if (a === 10) return true;
        if (a === 127) return true;
        if (a === 169 && b === 254) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
        return false;
    }
    if (family === 6) {
        const lower = address.toLowerCase();
        return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
    }
    return false;
}

function normalizePeerId(peerId) {
    if (peerId === undefined || peerId === null) return null;
    const str = String(peerId);
    if (!str || str.length > MAX_PEER_ID_LEN) return null;
    return str;
}

/**
 * UDP Hole Punching 实现
 * 用于 NAT 穿透，让两个位于不同 NAT 后的节点直接通信
 *
 * 安全说明：
 * - 推荐配置 `authToken`（双方共享密钥）。配置后所有 punch/punch-ack 都带
 *   HMAC-SHA256 签名 + 时间戳 + 随机 nonce，未通过校验的包直接丢弃。
 * - 未配置 `authToken` 时进入兼容模式：仅接受来自内网/回环地址的未认证 punch，
 *   公网来源的未认证 punch 一律忽略（防止反射放大与任意打洞）。
 * - 任何模式下都有消息大小、对端表大小与每源 IP 速率限制。
 */
class HolePuncher {
    constructor(options = {}) {
        if (typeof options === 'string' || Buffer.isBuffer(options)) {
            // 兼容 new HolePuncher(token)
            options = { authToken: options };
        }
        this.socket = null;
        this.localPort = 0;
        this.publicAddress = null;
        this.publicPort = 0;
        this.peers = new Map();
        this.state = 'closed';
        this.messageHandlers = new Map();

        this._authToken = options.authToken !== undefined && options.authToken !== null
            ? Buffer.isBuffer(options.authToken) ? options.authToken : Buffer.from(String(options.authToken), 'utf8')
            : null;
        if (this._authToken && this._authToken.length === 0) this._authToken = null;

        // 显式开启时，拒绝所有未认证 punch（即使来自内网）
        this._requireAuth = options.requireAuth === true || !!this._authToken;
        this._maxPeers = Number.isInteger(options.maxPeers) && options.maxPeers > 0
            ? Math.min(options.maxPeers, MAX_PEERS)
            : MAX_PEERS;

        this._maxMessageSize = Number.isInteger(options.maxMessageSize) && options.maxMessageSize > 0
            ? Math.min(options.maxMessageSize, MAX_DATA_LEN)
            : MAX_DATA_LEN;

        // 防重放：nonce -> 过期时间
        this._seenNonces = new Map();
        this._nonceSweepAt = 0;
        // 每 IP punch 计数（滑动 1s 窗口）
        this._punchBuckets = new Map();
        // 未完成的 punch 定时器，stop() 时清理
        this._punchTimers = new Set();
    }

    /**
     * 启动打洞器
     */
    async start(localPort = 0) {
        if (this.socket) return this.localPort;
        if (!Number.isInteger(localPort) || localPort < 0 || localPort > 65535) {
            throw new RangeError(`Invalid local port: ${localPort}`);
        }
        return new Promise((resolve, reject) => {
            this.socket = dgram.createSocket('udp4');

            this.socket.on('message', (msg, rinfo) => {
                this._handleMessage(msg, rinfo);
            });

            let settled = false;

            this.socket.on('error', (err) => {
                console.error('[HolePuncher] Socket error:', err);
                this.state = 'error';
                // bind 失败(端口占用/权限)时 Promise 必须 settle,否则调用方永远挂起
                if (!settled) {
                    settled = true;
                    try { this.socket.close(); } catch (e) { /* ignore */ }
                    this.socket = null;
                    reject(err);
                }
            });

            this.socket.on('listening', () => {
                const address = this.socket.address();
                this.localPort = address.port;
                this.state = 'ready';
                console.log(`[HolePuncher] Listening on port ${this.localPort}`);
                if (!settled) {
                    settled = true;
                    resolve(this.localPort);
                }
            });

            this.socket.bind(localPort);
        });
    }

    /**
     * 通过 STUN 服务器获取公网地址
     */
    async discoverPublicAddress(stunHost, stunPort = 3478) {
        return new Promise((resolve, reject) => {
            if (!this.socket || this.state === 'closed') {
                return reject(new Error('HolePuncher not started'));
            }
            if (typeof stunHost !== 'string' || !stunHost || stunHost.length > 255) {
                return reject(new Error('Invalid STUN host'));
            }
            if (!Number.isInteger(stunPort) || stunPort < 1 || stunPort > 65535) {
                return reject(new Error('Invalid STUN port'));
            }

            const transactionId = crypto.randomBytes(12);
            const message = Buffer.alloc(20);

            message.writeUInt16BE(0x0001, 0);  // Binding Request
            message.writeUInt16BE(0x0000, 2);  // Message Length
            message.writeUInt32BE(0x2112A442, 4); // Magic Cookie
            transactionId.copy(message, 8);

            let settled = false;
            const cleanup = () => {
                clearTimeout(timeout);
                if (this.socket) this.socket.removeListener('message', handler);
            };
            const fail = (err) => {
                if (settled) return;
                settled = true;
                cleanup();
                reject(err);
            };
            const succeed = (info) => {
                if (settled) return;
                settled = true;
                cleanup();
                resolve(info);
            };

            const handler = (msg) => {
                try {
                    if (!Buffer.isBuffer(msg) || msg.length < 20) return;

                    const type = msg.readUInt16BE(0);
                    if (type !== 0x0101) return;  // Binding Success Response
                    const cookie = msg.readUInt32BE(4);
                    if (cookie !== 0x2112A442) return;
                    if (!msg.slice(8, 20).equals(transactionId)) return;

                    // 解析 XOR-MAPPED-ADDRESS
                    let offset = 20;
                    while (offset + 4 <= msg.length) {
                        const attrType = msg.readUInt16BE(offset);
                        const attrLen = msg.readUInt16BE(offset + 2);
                        if (offset + 4 + attrLen > msg.length) break; // 畸形包保护

                        if (attrType === 0x0020) {  // XOR-MAPPED-ADDRESS
                            if (attrLen < 8) break; // 长度不足，畸形
                            const family = msg.readUInt8(offset + 5);
                            const xPort = msg.readUInt16BE(offset + 6);
                            const mask = [0x21, 0x12, 0xA4, 0x42];

                            const port = xPort ^ 0x2112;
                            const addrBytes = [];
                            for (let i = 0; i < 4; i++) addrBytes.push(msg.readUInt8(offset + 8 + i) ^ mask[i]);
                            const address = addrBytes.join('.');

                            if (family === 0x01) {
                                this.publicAddress = address;
                                this.publicPort = port;

                                console.log(`[HolePuncher] Public address: ${address}:${port}`);
                                succeed({ address, port, localPort: this.localPort });
                                return;
                            }
                        }

                        offset += 4 + attrLen + ((4 - (attrLen % 4)) % 4);
                    }
                } catch (e) {
                    fail(new Error(`STUN response parse error: ${e.message}`));
                }
            };

            const timeout = setTimeout(() => fail(new Error('STUN timeout')), 5000);

            // 先注册监听再发送,避免响应先于注册到达的竞态
            this.socket.on('message', handler);

            this.socket.send(message, stunPort, stunHost, (err) => {
                if (err) fail(err);
            });
        });
    }

    /**
     * 计算 punch/ack 的 HMAC 签名
     */
    _sign(fields) {
        return crypto.createHmac('sha256', this._authToken)
            .update(fields.join('|'))
            .digest('hex');
    }

    _makeSignature(payload, peerId, timestamp, nonce) {
        if (!this._authToken) return null;
        return this._sign(['punch', payload.type, peerId, String(timestamp), nonce]);
    }

    _safeEqualHex(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string') return false;
        const ba = Buffer.from(a, 'utf8');
        const bb = Buffer.from(b, 'utf8');
        if (ba.length !== bb.length) return false;
        return crypto.timingSafeEqual(ba, bb);
    }

    /**
     * 校验入站 punch / punch-ack 的认证信息。
     * @returns {{ok: boolean, reason?: string}}
     */
    _authenticateControl(data, rinfo) {
        const peerId = normalizePeerId(data.peerId);
        if (!peerId) return { ok: false, reason: 'invalid-peer-id' };

        // 有共享密钥：必须签名且校验通过
        if (this._authToken) {
            if (typeof data.sig !== 'string' || typeof data.nonce !== 'string' ||
                !Number.isFinite(data.timestamp)) {
                return { ok: false, reason: 'missing-signature' };
            }
            const age = Math.abs(Date.now() - data.timestamp);
            if (age > PUNCH_WINDOW_MS) return { ok: false, reason: 'stale-timestamp' };

            const expected = this._sign(['punch', data.type, peerId, String(data.timestamp), data.nonce]);
            if (!this._safeEqualHex(expected, data.sig.toLowerCase())) {
                return { ok: false, reason: 'bad-signature' };
            }

            // 防重放
            const now = Date.now();
            if (now > this._nonceSweepAt) {
                for (const [n, exp] of this._seenNonces) {
                    if (exp < now) this._seenNonces.delete(n);
                }
                this._nonceSweepAt = now + PUNCH_WINDOW_MS;
            }
            if (this._seenNonces.has(data.nonce)) return { ok: false, reason: 'replayed-nonce' };
            this._seenNonces.set(data.nonce, now + PUNCH_WINDOW_MS);
            if (this._seenNonces.size > 4096) {
                // 极端情况下清掉最旧的一半，保持有界
                let drop = Math.ceil(this._seenNonces.size / 2);
                for (const n of this._seenNonces.keys()) {
                    if (drop-- <= 0) break;
                    this._seenNonces.delete(n);
                }
            }

            return { ok: true, peerId };
        }

        // 兼容模式（无共享密钥）：只信任内网/回环来源
        if (this._requireAuth) return { ok: false, reason: 'auth-required' };
        if (!isPrivateAddress(rinfo && rinfo.address)) {
            return { ok: false, reason: 'unauthenticated-public-source' };
        }
        return { ok: true, peerId };
    }

    _rateLimitPunch(rinfo) {
        const key = rinfo && rinfo.address ? rinfo.address : 'unknown';
        const now = Date.now();
        let bucket = this._punchBuckets.get(key);
        if (!bucket || now - bucket.windowStart >= 1000) {
            bucket = { windowStart: now, count: 0 };
            this._punchBuckets.set(key, bucket);
            if (this._punchBuckets.size > 1024) {
                // 简单清理：移除过期桶
                for (const [k, b] of this._punchBuckets) {
                    if (now - b.windowStart >= 1000) this._punchBuckets.delete(k);
                }
            }
        }
        bucket.count++;
        return bucket.count <= MAX_PUNCH_PER_SEC;
    }

    /**
     * 向对端发送打洞请求
     */
    punch(targetAddress, targetPort, peerId) {
        if (!this.socket) {
            throw new Error('HolePuncher not started');
        }
        if (typeof targetAddress !== 'string' || !targetAddress || targetAddress.length > 255) {
            throw new TypeError('Invalid target address');
        }
        if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
            throw new RangeError(`Invalid target port: ${targetPort}`);
        }
        const normalizedPeerId = normalizePeerId(peerId);
        if (!normalizedPeerId) {
            throw new TypeError('Invalid peerId');
        }

        const timestamp = Date.now();
        const nonce = crypto.randomBytes(16).toString('hex');
        const payload = {
            type: 'punch',
            peerId: normalizedPeerId,
            timestamp,
            nonce
        };
        const sig = this._makeSignature(payload, normalizedPeerId, timestamp, nonce);
        if (sig) payload.sig = sig;

        const punchMessage = Buffer.from(JSON.stringify(payload));
        if (punchMessage.length > MAX_CONTROL_MESSAGE) {
            throw new Error('Punch message too large');
        }

        // 发送多个打洞包，增加成功率
        for (let i = 0; i < 3; i++) {
            const timer = setTimeout(() => {
                this._punchTimers.delete(timer);
                // stop() 之后 socket 已销毁,不能再发送
                if (!this.socket) return;
                this.socket.send(punchMessage, targetPort, targetAddress, (err) => {
                    if (err) {
                        console.error(`[HolePuncher] Punch error: ${err.message}`);
                    } else {
                        console.log(`[HolePuncher] Punched ${targetAddress}:${targetPort} (${i + 1}/3)`);
                    }
                });
            }, i * 100);
            this._punchTimers.add(timer);
        }

        // 记录对端信息
        this._setPeer(normalizedPeerId, targetAddress, targetPort);
    }

    _setPeer(peerId, address, port) {
        if (this.peers.size >= this._maxPeers && !this.peers.has(peerId)) {
            // 达到上限，淘汰最早加入的 peer
            const oldestKey = this.peers.keys().next().value;
            if (oldestKey !== undefined) this.peers.delete(oldestKey);
        }
        this.peers.set(peerId, { address, port });
    }

    /**
     * 发送数据
     */
    send(peerId, data) {
        const peer = this.peers.get(peerId);
        if (!peer) {
            throw new Error(`Unknown peer: ${peerId}`);
        }
        if (!this.socket) {
            throw new Error('HolePuncher not started');
        }

        const message = Buffer.isBuffer(data) ? data : Buffer.from(data);
        if (message.length > this._maxMessageSize) {
            throw new RangeError(`Payload too large: ${message.length} > ${this._maxMessageSize}`);
        }
        this.socket.send(message, peer.port, peer.address);
    }

    /**
     * 发送数据到指定地址
     */
    sendTo(address, port, data) {
        if (!this.socket) {
            throw new Error('HolePuncher not started');
        }
        if (typeof address !== 'string' || !address || address.length > 255) {
            throw new TypeError('Invalid target address');
        }
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            throw new RangeError(`Invalid target port: ${port}`);
        }
        const message = Buffer.isBuffer(data) ? data : Buffer.from(data);
        if (message.length > this._maxMessageSize) {
            throw new RangeError(`Payload too large: ${message.length} > ${this._maxMessageSize}`);
        }
        this.socket.send(message, port, address);
    }

    /**
     * 处理接收到的消息
     */
    _handleMessage(msg, rinfo) {
        if (!Buffer.isBuffer(msg) || msg.length === 0) return;
        if (msg.length > this._maxMessageSize) return;

        // 只尝试把较小的包当控制消息解析
        let data = null;
        if (msg.length <= MAX_CONTROL_MESSAGE) {
            try { data = JSON.parse(msg.toString()); } catch (e) { data = null; }
        }

        if (data && typeof data === 'object' && (data.type === 'punch' || data.type === 'punch-ack')) {
            if (!this._rateLimitPunch(rinfo)) return; // 防刷
            const auth = this._authenticateControl(data, rinfo);
            if (!auth.ok) {
                this._emitRaw('unauthenticated', { reason: auth.reason, rinfo, type: data.type });
                return;
            }

            if (data.type === 'punch') {
                console.log(`[HolePuncher] Received punch from ${rinfo.address}:${rinfo.port}`);
                // 回复确认（带签名，若已配置密钥）
                const timestamp = Date.now();
                const nonce = crypto.randomBytes(16).toString('hex');
                const ack = {
                    type: 'punch-ack',
                    peerId: auth.peerId,
                    timestamp,
                    nonce
                };
                const sig = this._makeSignature(ack, auth.peerId, timestamp, nonce);
                if (sig) ack.sig = sig;
                const ackBuf = Buffer.from(JSON.stringify(ack));
                if (ackBuf.length <= MAX_CONTROL_MESSAGE && this.socket) {
                    this.socket.send(ackBuf, rinfo.port, rinfo.address);
                }

                // 更新对端信息
                this._setPeer(auth.peerId, rinfo.address, rinfo.port);
            } else {
                console.log(`[HolePuncher] Punch acknowledged by ${rinfo.address}:${rinfo.port}`);
            }

            const handler = this.messageHandlers.get(data.type);
            if (handler) {
                try { handler(data, rinfo); } catch (e) {
                    console.error('[HolePuncher] Handler error:', e.message);
                }
            }
            return;
        }

        // 普通 JSON 自定义消息（如 ping / 数据包）：按 type 分发到对应处理器
        if (data && typeof data === 'object' && typeof data.type === 'string') {
            const handler = this.messageHandlers.get(data.type);
            if (handler) {
                try { handler(data, rinfo); } catch (e) {
                    console.error('[HolePuncher] Handler error:', e.message);
                }
                return;
            }
        }

        // 非 JSON 数据（或未注册 type 处理器）走 raw 处理器
        const rawHandler = this.messageHandlers.get('raw');
        if (rawHandler) {
            try { rawHandler(msg, rinfo); } catch (e) {
                console.error('[HolePuncher] Raw handler error:', e.message);
            }
        }
    }

    _emitRaw(event, payload) {
        const handler = this.messageHandlers.get(event);
        if (handler) {
            try { handler(payload); } catch (e) { /* ignore */ }
        }
    }

    /**
     * 注册消息处理器
     */
    on(event, handler) {
        if (typeof handler !== 'function') return;
        this.messageHandlers.set(event, handler);
    }

    /**
     * 停止打洞器
     */
    stop() {
        for (const timer of this._punchTimers) clearTimeout(timer);
        this._punchTimers.clear();
        if (this.socket) {
            try { this.socket.close(); } catch (e) { /* ignore */ }
            this.socket = null;
            this.state = 'closed';
        }
        this._punchBuckets.clear();
        this._seenNonces.clear();
    }

    /**
     * 获取本地端口
     */
    getLocalPort() {
        return this.localPort;
    }

    /**
     * 获取公网地址信息
     */
    getPublicAddress() {
        return { address: this.publicAddress, port: this.publicPort };
    }
}

HolePuncher.isPrivateAddress = isPrivateAddress;

module.exports = HolePuncher;
