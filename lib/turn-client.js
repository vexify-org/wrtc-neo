// © Vexify 2026 All Rights Reserved.
const dgram = require('dgram');
const net = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');

/**
 * TURN 客户端 — RFC 5766 完整实现
 * 支持 UDP/TCP TURN，用于对称 NAT 穿透
 */

// TURN 消息类型
const TURN_METHODS = {
    ALLOCATE: 0x003,
    REFRESH: 0x004,
    SEND: 0x006,
    DATA: 0x007,
    CREATE_PERMISSION: 0x008,
    CHANNEL_BIND: 0x009
};

const TURN_CLASSES = {
    REQUEST: 0x0000,
    INDICATION: 0x0010,
    SUCCESS: 0x0100,
    ERROR: 0x0110
};

// TURN 属性
const ATTRS = {
    MAPPED_ADDRESS: 0x0001,
    USERNAME: 0x0006,
    MESSAGE_INTEGRITY: 0x0008,
    ERROR_CODE: 0x0009,
    CHANNEL_NUMBER: 0x000C,
    LIFETIME: 0x000D,
    XOR_PEER_ADDRESS: 0x0012,
    DATA: 0x0013,
    REALM: 0x0014,
    NONCE: 0x0015,
    XOR_RELAYED_ADDRESS: 0x0016,
    REQUESTED_TRANSPORT: 0x0019,
    DONT_FRAGMENT: 0x001A,
    XOR_MAPPED_ADDRESS: 0x0020,
    SOFTWARE: 0x8022,
    ALTERNATE_SERVER: 0x8023,
    FINGERPRINT: 0x8028
};

class TurnClient extends EventEmitter {
    constructor(options = {}) {
        super();
        this._host = options.host || '127.0.0.1';
        this._port = options.port || 3478;
        this._username = options.username || '';
        this._credential = options.credential || '';
        this._transport = options.transport || 'udp';
        this._socket = null;
        this._state = 'idle';
        this._nonce = null;
        this._realm = null;
        this._relayedAddress = null;
        this._lifetime = 600;
        this._permissions = new Set();
        this._channelBindings = new Map(); // channelNumber -> peerAddr
        this._nextChannel = 0x4000;
        this._pendingRequests = new Map();
        this._refreshTimer = null;
        this._requestTimeout = 5000;
        this._hmacKey = null;
    }

    // ============================================================
    // 连接 & 分配
    // ============================================================
    async connect() {
        if (this._transport === 'tcp') {
            return this._connectTcp();
        }
        return this._connectUdp();
    }

    async _connectUdp() {
        this._socket = dgram.createSocket('udp4');
        this._socket.on('message', (msg) => this._handleMessage(msg));
        this._socket.on('error', (err) => this.emit('error', err));
        return new Promise((resolve) => {
            this._socket.bind(0, () => resolve());
        });
    }

    async _connectTcp() {
        return new Promise((resolve, reject) => {
            this._socket = new net.Socket();
            this._socket.connect(this._port, this._host, () => resolve());
            this._socket.on('error', (err) => { this.emit('error', err); reject(err); });
            this._socket.on('close', () => this.emit('close'));

            let buf = Buffer.alloc(0);
            this._socket.on('data', (chunk) => {
                buf = Buffer.concat([buf, chunk]);
                // TURN over TCP: 前 2 字节是消息长度
                while (buf.length >= 4) {
                    const len = buf.readUInt16BE(2) + 4; // 包含 padding
                    if (buf.length < len) break;
                    this._handleMessage(buf.slice(0, len));
                    buf = buf.slice(len);
                }
            });
        });
    }

    // ============================================================
    // TURN 分配
    // ============================================================
    // ============================================================
    // 请求（带 401 认证重试）
    // ============================================================
    _doRequest(method, attrs, label) {
        return new Promise((resolve, reject) => {
            const attempt = (auth) => {
                let msg = this._buildMessage(method);
                for (const [type, value] of attrs) {
                    msg = this._addAttribute(msg, type, value);
                }
                if (auth) msg = this._finalizeAuth(msg);
                const tid = msg.slice(8, 20).toString('hex');
                const timer = setTimeout(() => {
                    this._pendingRequests.delete(tid);
                    reject(new Error(`TURN ${label} timeout`));
                }, this._requestTimeout);
                this._pendingRequests.set(tid, { resolve, reject, method, label, auth, attempt });
                this._sendMessage(msg);
            };
            attempt(false);
        });
    }

    async allocate() {
        this._state = 'allocating';
        return this._doRequest(TURN_METHODS.ALLOCATE, [
            [ATTRS.REQUESTED_TRANSPORT, Buffer.from([0x11, 0x00, 0x00, 0x00])],
            [ATTRS.LIFETIME, this._intToBuffer(3600, 4)],
            [ATTRS.DONT_FRAGMENT, Buffer.alloc(0)]
        ], 'Allocate');
    }

    async createPermission(peerAddress, peerPort) {
        const addr = this._encodeXorAddress(peerAddress, peerPort);
        return this._doRequest(TURN_METHODS.CREATE_PERMISSION, [
            [ATTRS.XOR_PEER_ADDRESS, addr]
        ], 'CreatePermission');
    }

    async channelBind(channelNumber, peerAddress, peerPort) {
        const addr = this._encodeXorAddress(peerAddress, peerPort);
        return this._doRequest(TURN_METHODS.CHANNEL_BIND, [
            [ATTRS.CHANNEL_NUMBER, this._intToBuffer(channelNumber, 2)],
            [ATTRS.XOR_PEER_ADDRESS, addr]
        ], 'ChannelBind').then(() => {
            this._channelBindings.set(channelNumber, `${peerAddress}:${peerPort}`);
        });
    }

    async refresh(lifetime = 600) {
        return this._doRequest(TURN_METHODS.REFRESH, [
            [ATTRS.LIFETIME, this._intToBuffer(lifetime, 4)]
        ], 'Refresh');
    }

    // ============================================================
    // 数据发送（Send Indication 或 ChannelData）
    // ============================================================
    async sendToPeer(data, peerAddress, peerPort) {
        // 确保有权限
        const permKey = `${peerAddress}:${peerPort}`;
        if (!this._permissions.has(permKey)) {
            await this.createPermission(peerAddress, peerPort);
            this._permissions.add(permKey);
        }

        // 优先使用 ChannelData
        let channelNumber = null;
        for (const [ch, addr] of this._channelBindings) {
            if (addr === permKey) { channelNumber = ch; break; }
        }

        if (channelNumber) {
            return this._sendChannelData(channelNumber, data);
        }

        return this._sendIndication(data, peerAddress, peerPort);
    }

    _sendChannelData(channelNumber, data) {
        const buf = Buffer.alloc(4 + data.length);
        buf.writeUInt16BE(channelNumber, 0);
        buf.writeUInt16BE(data.length, 2);
        data.copy(buf, 4);
        this._sendRaw(buf);
    }

    _sendIndication(data, peerAddress, peerPort) {
        const msg = this._buildMessage(TURN_METHODS.SEND, TURN_CLASSES.INDICATION);
        const addr = this._encodeXorAddress(peerAddress, peerPort);
        this._addAttribute(msg, ATTRS.XOR_PEER_ADDRESS, addr);
        this._addAttribute(msg, ATTRS.DATA, data);
        this._sendMessage(msg);
    }

    // ============================================================
    // 消息构造
    // ============================================================
    _buildMessage(method, cls = TURN_CLASSES.REQUEST) {
        const msg = Buffer.alloc(20);
        msg.writeUInt16BE(cls | method, 0);
        msg.writeUInt16BE(0, 2); // length (filled later)
        msg.writeUInt32BE(0x2112A442, 4); // magic cookie
        // 12 bytes transaction ID
        for (let i = 8; i < 20; i++) msg.writeUInt8(Math.floor(Math.random() * 256), i);
        return msg;
    }

    _addAttribute(msg, type, value) {
        const padding = (4 - (value.length % 4)) % 4;
        const attr = Buffer.alloc(4 + value.length + padding);
        attr.writeUInt16BE(type, 0);
        attr.writeUInt16BE(value.length, 2);
        value.copy(attr, 4);

        // 追加到消息
        const newMsg = Buffer.alloc(msg.length + attr.length);
        msg.copy(newMsg);
        attr.copy(newMsg, msg.length);

        // 更新长度
        newMsg.writeUInt16BE(newMsg.length - 20, 2);
        return newMsg;
    }

    _finalizeAuth(msg) {
        if (!this._username) return msg;

        msg = this._addAttribute(msg, ATTRS.USERNAME, Buffer.from(this._username, 'utf8'));
        if (this._realm) msg = this._addAttribute(msg, ATTRS.REALM, Buffer.from(this._realm, 'utf8'));
        if (this._nonce) msg = this._addAttribute(msg, ATTRS.NONCE, Buffer.from(this._nonce, 'utf8'));

        // MESSAGE-INTEGRITY: HMAC-SHA1 over everything so far
        const key = crypto.createHash('md5')
            .update(`${this._username}:${this._realm || ''}:${this._credential}`, 'utf8')
            .digest();
        const hmac = crypto.createHmac('sha1', key).update(msg).digest();
        msg = this._addAttribute(msg, ATTRS.MESSAGE_INTEGRITY, hmac);

        // FINGERPRINT: CRC-32 of the whole message XOR 0x5354554E
        const crc = this._crc32(msg);
        msg = this._addAttribute(msg, ATTRS.FINGERPRINT, this._intToBuffer((crc ^ 0x5354554E) >>> 0, 4));
        return msg;
    }

    _crc32(buf) {
        let crc = 0xFFFFFFFF;
        for (let i = 0; i < buf.length; i++) {
            crc ^= buf.readUInt8(i);
            for (let j = 0; j < 8; j++) {
                crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
            }
        }
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    _encodeXorAddress(address, port) {
        const buf = Buffer.alloc(8);
        buf.writeUInt8(0, 0); // reserved
        buf.writeUInt8(0x01, 1); // IPv4
        buf.writeUInt16BE(port ^ 0x2112, 2); // XOR port (RFC 5769)
        const mask = [0x21, 0x12, 0xA4, 0x42];
        const parts = address.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            buf.writeUInt8(parts[i] ^ mask[i], 4 + i);
        }
        return buf;
    }

    _intToBuffer(value, bytes) {
        const buf = Buffer.alloc(bytes);
        if (bytes === 2) buf.writeUInt16BE(value, 0);
        else if (bytes === 4) buf.writeUInt32BE(value, 0);
        return buf;
    }

    // ============================================================
    // 消息处理
    // ============================================================
    _handleMessage(msg) {
        if (msg.length < 20) return;

        // 检查是否是 ChannelData
        const firstTwo = msg.readUInt16BE(0);
        if (firstTwo >= 0x4000 && firstTwo <= 0x7FFF) {
            this._handleChannelData(msg);
            return;
        }

        const type = msg.readUInt16BE(0);
        const cls = type & 0x0110;
        const method = type & 0x3EEF;
        const len = msg.readUInt16BE(2);
        const tid = msg.slice(8, 20).toString('hex');

        if (cls === TURN_CLASSES.SUCCESS) {
            this._handleSuccess(msg, method, tid);
        } else if (cls === TURN_CLASSES.ERROR) {
            this._handleError(msg, tid);
        } else if (method === TURN_METHODS.DATA) {
            this._handleDataIndication(msg);
        }
    }

    _handleChannelData(msg) {
        const channelNumber = msg.readUInt16BE(0);
        const dataLen = msg.readUInt16BE(2);
        const data = msg.slice(4, 4 + dataLen);

        const peerAddr = this._channelBindings.get(channelNumber);
        this.emit('data', { data, channelNumber, peerAddr });
    }

    _handleSuccess(msg, method, tid) {
        let offset = 20;
        const result = {};

        while (offset + 4 <= msg.length) {
            const attrType = msg.readUInt16BE(offset);
            const attrLen = msg.readUInt16BE(offset + 2);
            const attrVal = msg.slice(offset + 4, offset + 4 + attrLen);

            switch (attrType) {
                case ATTRS.XOR_RELAYED_ADDRESS: {
                    const decoded = this._decodeXorAddress(attrVal);
                    if (decoded) {
                        result.relayedAddress = decoded.address;
                        result.relayedPort = decoded.port;
                        this._relayedAddress = { address: decoded.address, port: decoded.port };
                    }
                    break;
                }
                case ATTRS.XOR_MAPPED_ADDRESS: {
                    const decoded = this._decodeXorAddress(attrVal);
                    if (decoded) {
                        result.mappedAddress = decoded.address;
                        result.mappedPort = decoded.port;
                    }
                    break;
                }
                case ATTRS.LIFETIME:
                    result.lifetime = attrVal.readUInt32BE(0);
                    this._lifetime = result.lifetime;
                    break;
                case ATTRS.NONCE:
                    this._nonce = attrVal.toString('ascii');
                    break;
                case ATTRS.REALM:
                    this._realm = attrVal.toString('ascii');
                    break;
            }

            offset += 4 + attrLen;
            // padding
            const pad = (4 - (attrLen % 4)) % 4;
            offset += pad;
        }

        const pending = this._pendingRequests.get(tid);
        if (pending) {
            this._pendingRequests.delete(tid);

            if (method === TURN_METHODS.ALLOCATE) {
                this._state = 'allocated';
                this._startRefresh();
                this.emit('allocated', result);
            }

            pending.resolve(result);
        }
    }

    _decodeXorAddress(attrVal) {
        if (attrVal.length < 8) return null;
        const family = attrVal.readUInt8(1);
        if (family !== 0x01) return null; // IPv4 only
        const port = attrVal.readUInt16BE(2) ^ 0x2112;
        const mask = [0x21, 0x12, 0xA4, 0x42];
        const ip = [];
        for (let i = 0; i < 4; i++) ip.push(attrVal.readUInt8(4 + i) ^ mask[i]);
        return { address: ip.join('.'), port };
    }

    _handleError(msg, tid) {
        let errorCode = 0;
        let errorReason = 'Unknown';
        let offset = 20;

        while (offset + 4 <= msg.length) {
            const attrType = msg.readUInt16BE(offset);
            const attrLen = msg.readUInt16BE(offset + 2);
            const attrVal = msg.slice(offset + 4, offset + 4 + attrLen);

            if (attrType === ATTRS.ERROR_CODE) {
                errorCode = (attrVal.readUInt8(2) * 100) + attrVal.readUInt8(3);
                errorReason = attrVal.slice(4).toString('ascii');
            }
            if (attrType === ATTRS.NONCE) {
                this._nonce = attrVal.toString('ascii');
            }
            if (attrType === ATTRS.REALM) {
                this._realm = attrVal.toString('ascii');
            }

            offset += 4 + attrLen;
            const pad = (4 - (attrLen % 4)) % 4;
            offset += pad;
        }

        const pending = this._pendingRequests.get(tid);
        if (pending) {
            this._pendingRequests.delete(tid);
            if (errorCode === 401 && !pending.auth && pending.attempt) {
                pending.attempt(true);
                return;
            }
            pending.reject(new Error(`TURN Error ${errorCode}: ${errorReason}`));
        }
    }

    _handleDataIndication(msg) {
        let offset = 20;
        let peerAddr = null;
        let data = null;

        while (offset + 4 <= msg.length) {
            const attrType = msg.readUInt16BE(offset);
            const attrLen = msg.readUInt16BE(offset + 2);
            const attrVal = msg.slice(offset + 4, offset + 4 + attrLen);

            if (attrType === ATTRS.XOR_PEER_ADDRESS) {
                const decoded = this._decodeXorAddress(attrVal);
                if (decoded) {
                    peerAddr = `${decoded.address}:${decoded.port}`;
                }
            }
            if (attrType === ATTRS.DATA) {
                data = attrVal;
            }

            offset += 4 + attrLen;
            const pad = (4 - (attrLen % 4)) % 4;
            offset += pad;
        }

        if (data && peerAddr) {
            this.emit('data', { data, peerAddr });
        }
    }

    // ============================================================
    // 发送
    // ============================================================
    _sendMessage(msg) {
        if (this._transport === 'tcp') {
            this._socket.write(msg);
        } else {
            this._socket.send(msg, this._port, this._host);
        }
    }

    _sendRaw(buf) {
        if (this._transport === 'tcp') {
            this._socket.write(buf);
        } else {
            this._socket.send(buf, this._port, this._host);
        }
    }

    _startRefresh() {
        this._refreshTimer = setInterval(async () => {
            try {
                await this.refresh(this._lifetime);
            } catch (e) {
                this.emit('error', new Error('TURN refresh failed: ' + e.message));
            }
        }, (this._lifetime - 60) * 1000);
    }

    // ============================================================
    // 关闭
    // ============================================================
    close() {
        this._state = 'closed';
        if (this._refreshTimer) {
            clearInterval(this._refreshTimer);
            this._refreshTimer = null;
        }
        if (this._socket) {
            this._socket.close();
            this._socket = null;
        }
        this._permissions.clear();
        this._channelBindings.clear();
        this._pendingRequests.clear();
    }

    get state() { return this._state; }
    get relayedAddress() { return this._relayedAddress; }
}

module.exports = TurnClient;