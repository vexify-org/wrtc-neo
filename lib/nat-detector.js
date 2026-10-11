// © Vexify 2026 All Rights Reserved.
const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');

/**
 * NAT 类型检测 — RFC 3489 协议
 * 检测 Full Cone / Restricted / Port Restricted / Symmetric NAT
 *
 * 关键实现点:
 *  - 全部测试共用同一 socket(同一本地源端口),否则映射地址比较无意义
 *  - 校验响应事务 ID,避免串包
 *  - 所有报文解析均有长度/异常保护,畸形包不会使进程崩溃
 */

const MAGIC_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_RESPONSE = 0x0101;
const ATTR_MAPPED_ADDRESS = 0x0001;
const ATTR_CHANGE_REQUEST = 0x0003;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;

const NAT_TYPES = {
    OPEN: 'open',
    FULL_CONE: 'full-cone',
    RESTRICTED: 'restricted',
    PORT_RESTRICTED: 'port-restricted',
    SYMMETRIC: 'symmetric',
    SYMMETRIC_FIREWALL: 'symmetric-firewall',
    BLOCKED: 'blocked'
};

class NatDetector {
    constructor(options = {}) {
        this._stunServer1 = options.stunServer1 || { host: 'stun.l.google.com', port: 19302 };
        this._stunServer2 = options.stunServer2 || { host: 'stun1.l.google.com', port: 19302 };
        this._timeout = options.timeout || 3000;
    }

    /**
     * 检测 NAT 类型
     * 测试流程(共用一个本地 socket / 源端口):
     * 1. Test I:   STUN 请求 → 有响应 = 非阻塞
     * 2. Test II:  同一 STUN 服务器 IP,不同端口 → 比较映射地址
     * 3. Test III: 不同 STUN 服务器 → 比较映射地址
     * 4. Test IV/V: CHANGE-REQUEST 判断 Restricted / Full Cone
     */
    async detect() {
        const result = {
            type: NAT_TYPES.BLOCKED,
            publicAddress: null,
            publicPort: null,
            details: {}
        };

        const socket = dgram.createSocket('udp4');
        try {
            // 绑定随机端口并保持,确保所有测试源端口一致
            await new Promise((resolve, reject) => {
                const onError = (err) => { socket.removeListener('listening', onListening); reject(err); };
                const onListening = () => { socket.removeListener('error', onError); resolve(); };
                socket.once('error', onError);
                socket.once('listening', onListening);
                socket.bind(0);
            });
        } catch (e) {
            try { socket.close(); } catch (e2) { /* ignore */ }
            result.error = e.message;
            return result;
        }

        try {
            // Test I: 基本 STUN 连通性
            const test1 = await this._stunRequest(socket, this._stunServer1);
            if (!test1) {
                result.type = NAT_TYPES.BLOCKED;
                return result;
            }

            result.publicAddress = test1.address;
            result.publicPort = test1.port;
            result.details.test1 = test1;

            // Test II: 同一服务器 IP,不同端口 → 检测对称 NAT
            const test2 = await this._stunRequest(socket, this._stunServer1, { changePort: true });
            result.details.test2 = test2;

            if (!test2) {
                result.type = NAT_TYPES.SYMMETRIC_FIREWALL;
                return result;
            }

            const sameMapping = test1.address === test2.address && test1.port === test2.port;
            if (!sameMapping) {
                result.type = NAT_TYPES.SYMMETRIC;
                return result;
            }

            // Test III: 不同服务器 → 再次确认映射一致
            const test3 = await this._stunRequest(socket, this._stunServer2);
            result.details.test3 = test3;

            if (!test3) {
                result.type = NAT_TYPES.SYMMETRIC_FIREWALL;
                return result;
            }

            const sameAddr = test1.address === test3.address && test1.port === test3.port;
            if (!sameAddr) {
                result.type = NAT_TYPES.SYMMETRIC;
                return result;
            }

            // 映射地址与本机任一非回环地址相同 → 公网直连(无 NAT)
            if (this._isLocalAddress(test1.address)) {
                result.type = NAT_TYPES.OPEN;
                return result;
            }

            // Test IV: CHANGE-REQUEST(不同 IP + 不同端口)→ Full Cone 判断
            const test4 = await this._stunChangeRequest(socket, this._stunServer1, false);
            result.details.test4 = test4;

            if (test4) {
                result.type = NAT_TYPES.FULL_CONE;
                return result;
            }

            // Test V: CHANGE-REQUEST(仅不同端口)→ Restricted vs Port Restricted
            const test5 = await this._stunChangeRequest(socket, this._stunServer1, true);
            result.details.test5 = test5;

            result.type = test5 ? NAT_TYPES.RESTRICTED : NAT_TYPES.PORT_RESTRICTED;
            return result;
        } finally {
            try { socket.close(); } catch (e) { /* ignore */ }
        }
    }

    /**
     * 快速检测(仅区分对称 NAT vs 非对称)
     */
    async quickDetect() {
        const socket = dgram.createSocket('udp4');
        try {
            await new Promise((resolve, reject) => {
                const onError = (err) => { socket.removeListener('listening', onListening); reject(err); };
                const onListening = () => { socket.removeListener('error', onError); resolve(); };
                socket.once('error', onError);
                socket.once('listening', onListening);
                socket.bind(0);
            });
        } catch (e) {
            try { socket.close(); } catch (e2) { /* ignore */ }
            return { type: NAT_TYPES.BLOCKED, error: e.message };
        }

        try {
            const test1 = await this._stunRequest(socket, this._stunServer1);
            if (!test1) return { type: NAT_TYPES.BLOCKED };

            const test2 = await this._stunRequest(socket, this._stunServer1, { changePort: true });
            if (!test2) return { type: NAT_TYPES.SYMMETRIC_FIREWALL };

            const same = test1.address === test2.address && test1.port === test2.port;
            return {
                type: same ? NAT_TYPES.FULL_CONE : NAT_TYPES.SYMMETRIC,
                publicAddress: test1.address,
                publicPort: test1.port
            };
        } finally {
            try { socket.close(); } catch (e) { /* ignore */ }
        }
    }

    /**
     * 发送 STUN Binding Request,返回映射地址。
     * @param {dgram.Socket} socket 复用的 socket(保证源端口一致)
     * @param {{host,port}} server
     * @param {{changePort?:boolean}} [opts]
     */
    _stunRequest(socket, server, opts = {}) {
        return new Promise((resolve) => {
            const tid = crypto.randomBytes(12);
            const msg = Buffer.alloc(20);
            msg.writeUInt16BE(STUN_BINDING_REQUEST, 0);
            msg.writeUInt16BE(0, 2); // length
            msg.writeUInt32BE(MAGIC_COOKIE, 4);
            tid.copy(msg, 8);

            const port = opts.changePort ? server.port + 1 : server.port;

            let settled = false;
            const done = (value) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                socket.removeListener('message', onMessage);
                resolve(value);
            };

            const timer = setTimeout(() => done(null), this._timeout);

            const onMessage = (resp) => {
                try {
                    if (!Buffer.isBuffer(resp) || resp.length < 20) return;
                    if (resp.readUInt16BE(0) !== STUN_BINDING_RESPONSE) return;
                    // 校验事务 ID
                    if (resp.slice(8, 20).compare(tid) !== 0) return;

                    const parsed = this._parseMappedAddress(resp, tid);
                    if (parsed) done(parsed);
                } catch (e) {
                    done(null);
                }
            };

            socket.on('message', onMessage);
            socket.once('error', () => done(null));

            try {
                socket.send(msg, port, server.host, (err) => { if (err) done(null); });
            } catch (e) {
                done(null);
            }
        });
    }

    /**
     * 发送带 CHANGE-REQUEST 的请求,判断是否有来自不同 IP/端口的回包。
     * @param {boolean} changePortOnly true = 仅换端口; false = 换 IP + 端口
     */
    _stunChangeRequest(socket, server, changePortOnly = false) {
        return new Promise((resolve) => {
            const tid = crypto.randomBytes(12);

            const msg = Buffer.alloc(28);
            msg.writeUInt16BE(STUN_BINDING_REQUEST, 0);
            msg.writeUInt16BE(8, 2); // 8 bytes attribute
            msg.writeUInt32BE(MAGIC_COOKIE, 4);
            tid.copy(msg, 8);

            msg.writeUInt16BE(ATTR_CHANGE_REQUEST, 20);
            msg.writeUInt16BE(4, 22);
            // change-ip(0x4) | change-port(0x2)
            msg.writeUInt32BE(changePortOnly ? 0x00000002 : 0x00000006, 24);

            let settled = false;
            const done = (value) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                socket.removeListener('message', onMessage);
                resolve(value);
            };

            const timer = setTimeout(() => done(false), this._timeout);

            const onMessage = (resp) => {
                try {
                    if (!Buffer.isBuffer(resp) || resp.length < 20) return;
                    if (resp.readUInt16BE(0) !== STUN_BINDING_RESPONSE) return;
                    if (resp.slice(8, 20).compare(tid) !== 0) return;
                    done(true);
                } catch (e) {
                    /* 忽略畸形包 */
                }
            };

            socket.on('message', onMessage);
            socket.once('error', () => done(false));

            try {
                socket.send(msg, server.port, server.host, (err) => { if (err) done(false); });
            } catch (e) {
                done(false);
            }
        });
    }

    /** 从 Binding Response 提取 XOR-MAPPED-ADDRESS / MAPPED-ADDRESS */
    _parseMappedAddress(resp, tid) {
        let offset = 20;
        while (offset + 4 <= resp.length) {
            const attrType = resp.readUInt16BE(offset);
            const attrLen = resp.readUInt16BE(offset + 2);
            const attrStart = offset + 4;
            if (attrStart + attrLen > resp.length) break; // 截断的畸形属性
            const attrVal = resp.slice(attrStart, attrStart + attrLen);

            if (attrType === ATTR_XOR_MAPPED_ADDRESS && attrLen >= 8) {
                const family = attrVal.readUInt8(1);
                const xorPort = attrVal.readUInt16BE(2);
                const port = xorPort ^ (MAGIC_COOKIE >>> 16);
                if (family === 0x01) {
                    const ip = [];
                    for (let i = 0; i < 4; i++) {
                        ip.push(attrVal.readUInt8(4 + i) ^ ((MAGIC_COOKIE >>> (24 - 8 * i)) & 0xff));
                    }
                    return { address: ip.join('.'), port };
                }
            }

            if (attrType === ATTR_MAPPED_ADDRESS && attrLen >= 8) {
                const family = attrVal.readUInt8(1);
                const port = attrVal.readUInt16BE(2);
                if (family === 0x01) {
                    const ip = Array.from(attrVal.slice(4, 8)).join('.');
                    return { address: ip, port };
                }
            }

            // 属性按 4 字节对齐
            offset = attrStart + attrLen + ((4 - (attrLen % 4)) % 4);
        }
        return null;
    }

    /** 判断地址是否为本机地址(用于识别 OPEN / 无 NAT) */
    _isLocalAddress(address) {
        try {
            const ifaces = os.networkInterfaces();
            for (const list of Object.values(ifaces)) {
                for (const info of list || []) {
                    if (info.family === 'IPv4' && info.address === address) return true;
                }
            }
        } catch (e) { /* ignore */ }
        return false;
    }
}

NatDetector.NAT_TYPES = NAT_TYPES;

module.exports = NatDetector;
