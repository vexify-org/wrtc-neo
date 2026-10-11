// © Vexify 2026 All Rights Reserved.
const dgram = require('dgram');
const crypto = require('crypto');

/**
 * UDP Hole Punching 实现
 * 用于 NAT 穿透，让两个位于不同 NAT 后的节点直接通信
 */
class HolePuncher {
    constructor() {
        this.socket = null;
        this.localPort = 0;
        this.publicAddress = null;
        this.publicPort = 0;
        this.peers = new Map();
        this.state = 'closed';
        this.messageHandlers = new Map();
    }

    /**
     * 启动打洞器
     */
    async start(localPort = 0) {
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

                        if (attrType === 0x0020 && attrLen >= 8) {  // XOR-MAPPED-ADDRESS
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
     * 向对端发送打洞请求
     */
    punch(targetAddress, targetPort, peerId) {
        if (!this.socket) {
            throw new Error('HolePuncher not started');
        }

        // 发送多个打洞包，增加成功率
        const punchMessage = Buffer.from(JSON.stringify({
            type: 'punch',
            peerId,
            timestamp: Date.now()
        }));

        for (let i = 0; i < 3; i++) {
            setTimeout(() => {
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
        }

        // 记录对端信息
        this.peers.set(peerId, { address: targetAddress, port: targetPort });
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
        this.socket.send(message, peer.port, peer.address);
    }

    /**
     * 发送数据到指定地址
     */
    sendTo(address, port, data) {
        if (!this.socket) {
            throw new Error('HolePuncher not started');
        }
        const message = Buffer.isBuffer(data) ? data : Buffer.from(data);
        this.socket.send(message, port, address);
    }

    /**
     * 处理接收到的消息
     */
    _handleMessage(msg, rinfo) {
        try {
            // 尝试解析 JSON
            const data = JSON.parse(msg.toString());

            if (data.type === 'punch') {
                console.log(`[HolePuncher] Received punch from ${rinfo.address}:${rinfo.port}`);
                // 回复确认
                const ack = Buffer.from(JSON.stringify({
                    type: 'punch-ack',
                    peerId: data.peerId
                }));
                if (this.socket) this.socket.send(ack, rinfo.port, rinfo.address);

                // 更新对端信息
                this.peers.set(data.peerId, { address: rinfo.address, port: rinfo.port });
            }

            if (data.type === 'punch-ack') {
                console.log(`[HolePuncher] Punch acknowledged by ${rinfo.address}:${rinfo.port}`);
            }

            // 触发自定义消息处理器
            const handler = this.messageHandlers.get(data.type);
            if (handler) {
                handler(data, rinfo);
            }

        } catch (e) {
            // 非 JSON 数据，可能是原始数据包
            // 触发原始数据处理器
            const rawHandler = this.messageHandlers.get('raw');
            if (rawHandler) {
                rawHandler(msg, rinfo);
            }
        }
    }

    /**
     * 注册消息处理器
     */
    on(event, handler) {
        this.messageHandlers.set(event, handler);
    }

    /**
     * 停止打洞器
     */
    stop() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
            this.state = 'closed';
        }
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

module.exports = HolePuncher;