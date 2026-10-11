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
        this.component = pick(init.component, parsed.component);
        this.protocol = pick(init.protocol, parsed.protocol);
        this.priority = pick(init.priority, parsed.priority);
        this.address = pick(init.address, parsed.address);
        this.port = pick(init.port, parsed.port);
        this.relatedAddress = pick(init.relatedAddress, parsed.relatedAddress);
        this.relatedPort = pick(init.relatedPort, parsed.relatedPort);
        this.tcpType = pick(init.tcpType, parsed.tcpType);
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

        let s = candidateStr.trim();
        if (s.startsWith('candidate:')) s = s.substring('candidate:'.length);
        if (s.startsWith('a=candidate:')) s = s.substring('a=candidate:'.length);

        const parts = s.split(/\s+/).filter(Boolean);
        // foundation component proto priority ip port typ <type> = 最少 8 段
        if (parts.length < 8) return out;
        if (parts[6] !== 'typ') return out;

        out.foundation = parts[0];

        const component = parseInt(parts[1], 10);
        out.component = Number.isNaN(component) ? 1 : component;

        out.protocol = parts[2].toLowerCase();

        const priority = parseInt(parts[3], 10);
        out.priority = Number.isNaN(priority) ? null : priority;

        out.address = parts[4];

        const port = parseInt(parts[5], 10);
        out.port = Number.isNaN(port) ? null : port;

        out.candidateType = parts[7];

        let i = 8;
        while (i + 1 < parts.length) {
            const attr = parts[i];
            const val = parts[i + 1];
            switch (attr) {
                case 'raddr':
                    out.relatedAddress = val;
                    i += 2;
                    break;
                case 'rport': {
                    const p = parseInt(val, 10);
                    out.relatedPort = Number.isNaN(p) ? null : p;
                    i += 2;
                    break;
                }
                case 'tcptype':
                    out.tcpType = val;
                    i += 2;
                    break;
                case 'ufrag':
                    out.usernameFragment = val;
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
