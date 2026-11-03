const net = require('net');

const MAX_CANDIDATE_LEN = 2048;
const MAX_ADDRESS_LEN = 255;

/** 校验端口：合法范围 0-65535，非法返回 null */
function sanitizePort(value) {
    const n = typeof value === 'number' ? value : parseInt(value, 10);
    if (!Number.isFinite(n) || !Number.isInteger(n)) return null;
    if (n < 0 || n > 65535) return null;
    return n;
}

/** 校验 IPv4/IPv6，或允许的 mDNS/主机名格式 */
function sanitizeAddress(value) {
    if (typeof value !== 'string' || !value || value.length > MAX_ADDRESS_LEN) return null;
    if (/\s/.test(value)) return null;
    if (net.isIP(value)) return value;
    // mDNS / hostname: RFC 1123 允许的字符，且不允许 CRLF/空格
    if (/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(value)) return value;
    return null;
}

/**
 * RTCIceCandidate — 兼容 W3C WebRTC API 的 ICE 候选实现
 *
 * 支持两种构造方式:
 *   1. 标准: new RTCIceCandidate({ candidate: 'candidate:1 1 UDP 2130706431 1.2.3.4 5000 typ host', sdpMid, sdpMLineIndex })
 *   2. 预解析字段: { candidate, foundation, priority, address, port, candidateType, ... }
 *
 * candidate 字符串会被自动解析为结构化字段(foundation/component/protocol/
 * priority/address/port/candidateType/relatedAddress/relatedPort/tcpType)。
 */
class RTCIceCandidate {
    constructor(init) {
        if (!init || typeof init !== 'object') {
            throw new TypeError('RTCIceCandidate constructor requires an object');
        }

        let candidateStr = init.candidate || '';
        if (typeof candidateStr !== 'string') {
            throw new TypeError('candidate must be a string');
        }
        if (candidateStr.length > MAX_CANDIDATE_LEN) {
            throw new RangeError(`candidate string too long (max ${MAX_CANDIDATE_LEN})`);
        }

        // 向后兼容: 旧代码通过 `type: <完整 candidate 字符串>` 传入触发解析
        let typeHint = init.type !== undefined ? init.type : undefined;
        if (typeof typeHint === 'string' && /\btyp\s+\S+/.test(typeHint)) {
            if (!candidateStr) candidateStr = typeHint;
            typeHint = undefined;
        }

        this.candidate = candidateStr;
        this.sdpMid = init.sdpMid !== undefined && init.sdpMid !== null ? init.sdpMid : null;
        this.sdpMLineIndex = init.sdpMLineIndex !== undefined && init.sdpMLineIndex !== null ? init.sdpMLineIndex : null;
        this.usernameFragment = init.usernameFragment !== undefined && init.usernameFragment !== null ? init.usernameFragment : null;

        const parsed = RTCIceCandidate.parse(candidateStr);

        const pick = (explicit, parsedVal) => {
            if (explicit !== undefined && explicit !== null) return explicit;
            return parsedVal !== undefined ? parsedVal : null;
        };

        this.foundation = pick(init.foundation, parsed.foundation);
        if (this.foundation !== null && this.foundation !== undefined) {
            this.foundation = String(this.foundation);
            if (this.foundation.length > 64) this.foundation = this.foundation.substring(0, 64);
        }

        const component = parseInt(pick(init.component, parsed.component), 10);
        // RFC 8445: component-id 为 1..256
        this.component = Number.isInteger(component) && component >= 1 && component <= 256 ? component : 1;

        const protocol = pick(init.protocol, parsed.protocol);
        this.protocol = typeof protocol === 'string' ? protocol.toLowerCase().substring(0, 16) : null;

        const priority = pick(init.priority, parsed.priority);
        this.priority = Number.isInteger(priority) && priority >= 0 && priority <= 0xFFFFFFFF ? priority : null;

        const address = pick(init.address, parsed.address);
        this.address = sanitizeAddress(address);

        const port = pick(init.port, parsed.port);
        this.port = sanitizePort(port);

        const relatedAddress = pick(init.relatedAddress, parsed.relatedAddress);
        this.relatedAddress = sanitizeAddress(relatedAddress);

        this.relatedPort = sanitizePort(pick(init.relatedPort, parsed.relatedPort));

        const tcpType = pick(init.tcpType, parsed.tcpType);
        this.tcpType = typeof tcpType === 'string' ? tcpType.substring(0, 16) : null;

        this.candidateType = pick(init.candidateType, parsed.candidateType);
        if (typeHint !== undefined && typeHint !== null && !this.candidateType) {
            this.candidateType = typeHint;
        }
    }

    toJSON() {
        return {
            candidate: this.candidate,
            sdpMid: this.sdpMid,
            sdpMLineIndex: this.sdpMLineIndex,
            usernameFragment: this.usernameFragment
        };
    }

    /**
     * 兼容属性: `type` 返回候选类型 (host / srflx / prflx / relay)。
     * setter 兼容旧用法(传入完整 candidate 字符串时自动解析)。
     */
    get type() {
        return this.candidateType;
    }

    set type(value) {
        if (typeof value === 'string' && /\btyp\s+\S+/.test(value) && !this.candidateType) {
            const parsed = RTCIceCandidate.parse(value);
            this.candidateType = parsed.candidateType !== undefined ? parsed.candidateType : null;
        } else {
            this.candidateType = value !== undefined ? value : null;
        }
    }

    /**
     * 解析 candidate 字符串(可带或去掉 `candidate:` 前缀)。
     * 格式: <foundation> <component> <proto> <priority> <ip> <port> typ <type> [raddr ..] [rport ..] [tcptype ..] [generation ..] ...
     */
    static parse(candidateStr) {
        const out = {};
        if (!candidateStr || typeof candidateStr !== 'string') return out;
        if (candidateStr.length > MAX_CANDIDATE_LEN) return out; // 超长输入直接视为无效，避免正则/分配压力

        let s = candidateStr.trim();
        if (s.startsWith('candidate:')) s = s.substring('candidate:'.length);
        if (s.startsWith('a=candidate:')) s = s.substring('a=candidate:'.length);

        const parts = s.split(/\s+/).filter(Boolean);
        // foundation component proto priority ip port typ <type> = 最少 8 段
        if (parts.length < 8) return out;
        if (parts[6] !== 'typ') return out;

        out.foundation = parts[0].substring(0, 64);

        const component = parseInt(parts[1], 10);
        out.component = !Number.isInteger(component) || component < 1 || component > 256 ? 1 : component;

        const protocol = parts[2].toLowerCase();
        out.protocol = protocol.length <= 16 ? protocol : null;

        const priority = parseInt(parts[3], 10);
        out.priority = Number.isInteger(priority) && priority >= 0 && priority <= 0xFFFFFFFF ? priority : null;

        out.address = sanitizeAddress(parts[4]);

        const port = parseInt(parts[5], 10);
        out.port = sanitizePort(port);

        const candidateType = parts[7];
        out.candidateType = candidateType.length <= 16 ? candidateType : null;

        let i = 8;
        while (i + 1 < parts.length) {
            const attr = parts[i];
            const val = parts[i + 1];
            switch (attr) {
                case 'raddr':
                    out.relatedAddress = sanitizeAddress(val);
                    i += 2;
                    break;
                case 'rport': {
                    const p = parseInt(val, 10);
                    out.relatedPort = sanitizePort(p);
                    i += 2;
                    break;
                }
                case 'tcptype':
                    out.tcpType = typeof val === 'string' ? val.substring(0, 16) : null;
                    i += 2;
                    break;
                case 'ufrag':
                    out.usernameFragment = typeof val === 'string' ? val.substring(0, 256) : null;
                    i += 2;
                    break;
                case 'generation':
                case 'network-id':
                case 'network-cost':
                case 'foundation':
                default:
                    i += 2;
                    break;
            }
        }

        return out;
    }

    /** 判断字符串是否是合法的 ICE candidate 行 */
    static isValid(candidateStr) {
        const p = RTCIceCandidate.parse(candidateStr);
        return !!p.candidateType;
    }
}

module.exports = RTCIceCandidate;
