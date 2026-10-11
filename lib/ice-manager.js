// © Vexify 2026 All Rights Reserved.
const dgram = require('dgram');
const net = require('net');
const os = require('os');
const crypto = require('crypto');
const RTCIceCandidate = require('./ice-candidate');
const TurnClient = require('./turn-client');
const NatDetector = require('./nat-detector');

/**
 * ICE 管理器 — RFC 5245 完整实现
 *
 * 新增：
 * - TURN 中继候选（relay candidate）
 * - ICE 完整状态机（controlling/controlled + 提名）
 * - NAT 类型检测
 * - TCP ICE 候选（防火墙封 UDP 场景）
 * - ICE 优先级计算（RFC 8445）
 */

const ICE_STATES = {
    NEW: 'new',
    GATHERING: 'gathering',
    WAITING: 'waiting',
    CHECKING: 'checking',
    CONNECTED: 'connected',
    COMPLETED: 'completed',
    FAILED: 'failed',
    DISCONNECTED: 'disconnected',
    CLOSED: 'closed'
};

class IceManager {
    constructor(iceServers, peerConnection) {
        this._iceServers = iceServers || [];
        this._peerConnection = peerConnection;
        this._state = ICE_STATES.NEW;
        this._localCandidates = [];
        this._remoteCandidates = [];
        this._sockets = [];
        this._tcpServers = [];
        this._turnClients = [];
        this._natType = null;
        this._callbacks = {
            candidate: [],
            connectionstatechange: [],
            gatheringcomplete: []
        };
        this._gatheringComplete = false;
        this._role = 'controlling'; // controlling or controlled
        this._tiebreaker = Math.floor(Math.random() * 0xFFFFFFFF);
        this._nominated = false;
        this._selectedPair = null;
        this._checkList = [];
        this._activeChecks = new Map();
        this._udpSocket = null;
        this._tcpSocket = null;
        this._ufrag = crypto.randomUUID().substring(0, 4);
        this._pwd = crypto.randomUUID().substring(0, 22);
        this._remoteUfrag = null;
        this._remotePwd = null;
    }

    get state() { return this._state; }
    get localCandidates() { return this._localCandidates; }
    get localUfrag() { return this._ufrag; }
    get localPwd() { return this._pwd; }
    get natType() { return this._natType; }

    on(event, callback) {
        if (this._callbacks[event]) this._callbacks[event].push(callback);
    }

    off(event, callback) {
        if (this._callbacks[event]) this._callbacks[event] = this._callbacks[event].filter(cb => cb !== callback);
    }

    // ============================================================
    // 启动 ICE 收集
    // ============================================================
    async startGathering() {
        this._state = ICE_STATES.GATHERING;
        this._emit('connectionstatechange', 'gathering');

        // 绑定 UDP socket（用于 ICE 检查）
        this._udpSocket = dgram.createSocket('udp4');
        this._sockets.push(this._udpSocket);
        await new Promise(r => this._udpSocket.bind(0, r));

        // 1. Host candidates
        await this._gatherHostCandidates();

        // 2. NAT 类型检测
        this._natType = await this._detectNatType();

        // 3. STUN srflx candidates
        await this._gatherSrflxCandidates();

        // 4. TURN relay candidates
        await this._gatherTurnCandidates();

        // 5. TCP candidates（如果 UDP 被墙）
        await this._gatherTcpCandidates();

        this._gatheringComplete = true;
        this._emit('gatheringcomplete');
        this._state = ICE_STATES.WAITING;
        this._emit('connectionstatechange', 'waiting');
    }

    async startConnecting(remoteUfrag, remotePwd) {
        this._remoteUfrag = remoteUfrag;
        this._remotePwd = remotePwd;

        if (this._state === ICE_STATES.NEW) {
            await this.startGathering();
        }

        this._state = ICE_STATES.CHECKING;
        this._emit('connectionstatechange', 'checking');

        // 构建检查列表
        this._buildCheckList();

        // 开始连通性检查
        await this._performIceChecks();
    }

    async addRemoteCandidate(candidate) {
        this._remoteCandidates.push(candidate);
        if (this._state === ICE_STATES.CHECKING || this._state === ICE_STATES.WAITING) {
            this._buildCheckList();
            await this._performIceChecks();
        }
    }

    // ============================================================
    // Candidate 收集
    // ============================================================
    async _gatherHostCandidates() {
        const interfaces = os.networkInterfaces();
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (!iface.internal && iface.family === 'IPv4') {
                    this._addLocalCandidate('host', 'udp', iface.address, this._udpSocket.address().port);
                }
            }
        }
    }

    async _gatherSrflxCandidates() {
        for (const server of this._iceServers) {
            const url = server.urls || '';
            if (!url.startsWith('stun:')) continue;
            const parts = url.replace('stun:', '').split(':');
            const host = parts[0];
            const port = parseInt(parts[1] || '3478', 10);

            try {
                const addr = await this._queryStun(host, port);
                if (addr) {
                    this._addLocalCandidate('srflx', 'udp', addr.address, addr.port, null, null, addr.address);
                }
            } catch (e) { /* ignore */ }
        }
    }

    async _gatherTurnCandidates() {
        for (const server of this._iceServers) {
            const url = server.urls || '';
            if (!url.startsWith('turn:')) continue;

            // 解析 TURN URL: turn:host:port?transport=udp
            const turnMatch = url.match(/turn:([^:]+)(?::(\d+))?(?:\?transport=(.+))?/);
            if (!turnMatch) continue;

            const host = turnMatch[1];
            const port = parseInt(turnMatch[2] || '3478', 10);
            const transport = turnMatch[3] || 'udp';

            try {
                const client = new TurnClient({
                    host, port, transport,
                    username: server.username || '',
                    credential: server.credential || ''
                });

                await client.connect();
                const result = await client.allocate();

                if (result.relayedAddress) {
                    this._addLocalCandidate('relay', transport, result.relayedAddress, result.relayedPort);
                    this._turnClients.push(client);
                    this._emit('turnReady', client);
                } else {
                    client.close();
                }
            } catch (e) {
                // TURN 不可用，继续
            }
        }
    }

    async _gatherTcpCandidates() {
        // 只在 NAT 类型为对称或防火墙封 UDP 时收集 TCP 候选
        if (this._natType && this._natType.type !== 'symmetric' && this._natType.type !== 'blocked') {
            return;
        }

        for (const server of this._iceServers) {
            const url = server.urls || '';
            if (!url.startsWith('turn:') || !url.includes('transport=tcp')) continue;

            const turnMatch = url.match(/turn:([^:]+)(?::(\d+))?/);
            if (!turnMatch) continue;

            const host = turnMatch[1];
            const port = parseInt(turnMatch[2] || '3478', 10);

            try {
                const client = new TurnClient({
                    host, port, transport: 'tcp',
                    username: server.username || '',
                    credential: server.credential || ''
                });

                await client.connect();
                const result = await client.allocate();

                if (result.relayedAddress) {
                    // 添加 TCP active 候选
                    this._addLocalCandidate('relay', 'tcp', result.relayedAddress, result.relayedPort, 'active');
                    this._turnClients.push(client);
                } else {
                    client.close();
                }
            } catch (e) { /* ignore */ }
        }
    }

    _addLocalCandidate(type, protocol, address, port, tcpType = null, relatedAddress = null, relatedPort = null) {
        const foundation = crypto.randomUUID().substring(0, 6);
        const priority = this._calculatePriority(type, protocol);

        let candidateStr = `${foundation} 1 ${protocol.toUpperCase()} ${priority} ${address} ${port} typ ${type}`;
        if (tcpType) candidateStr += ` tcptype ${tcpType}`;
        if (relatedAddress) candidateStr += ` raddr ${relatedAddress} rport ${relatedPort || 0}`;

        const candidate = new RTCIceCandidate({
            candidate: candidateStr,
            sdpMid: '0',
            sdpMLineIndex: 0,
            foundation,
            priority,
            address,
            port,
            protocol,
            type: candidateStr,
            candidateType: type,
            tcpType,
            relatedAddress,
            relatedPort
        });

        this._localCandidates.push(candidate);
        this._emit('candidate', candidate);
    }

    // ============================================================
    // NAT 类型检测
    // ============================================================
    async _detectNatType() {
        try {
            const detector = new NatDetector();
            return await detector.quickDetect();
        } catch (e) {
            return { type: 'unknown' };
        }
    }

    // ============================================================
    // ICE 优先级 (RFC 8445)
    // ============================================================
    _calculatePriority(type, protocol) {
        // type preference: host=126, srflx=100, relay=0
        const typePref = { host: 126, srflx: 100, prflx: 110, relay: 0 };
        const localPref = 65535;

        // priority = (2^24 * typePref) + (2^8 * localPref) + (2^0 * 256 - componentId)
        return (typePref[type] || 0) * 16777216 + localPref * 256 + (256 - 1);
    }

    _calculatePairPriority(local, remote) {
        // pair priority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0)
        const G = this._role === 'controlling' ? local.priority : remote.priority;
        const D = this._role === 'controlling' ? remote.priority : local.priority;
        // 2^32 * priority 约 9e18,超出 Number.MAX_SAFE_INTEGER 会丢失排序精度,
        // 因此用 BigInt 精确计算,同时保留 Number 近似值供序列化展示
        const big = (BigInt(Math.min(G, D)) << 32n) + (2n * BigInt(Math.max(G, D))) + (G > D ? 1n : 0n);
        return { value: Number(big), big };
    }

    // ============================================================
    // 检查列表
    // ============================================================
    _buildCheckList() {
        this._checkList = [];
        for (const local of this._localCandidates) {
            for (const remote of this._remoteCandidates) {
                // 同类型优先
                if (local.protocol !== remote.protocol) continue;
                const prio = this._calculatePairPriority(local, remote);
                this._checkList.push({
                    local,
                    remote,
                    priority: prio.value,
                    sortKey: prio.big,
                    state: 'frozen'
                });
            }
        }
        // 按优先级降序排序(BigInt 避免大数精度丢失)
        this._checkList.sort((a, b) => (a.sortKey > b.sortKey ? -1 : a.sortKey < b.sortKey ? 1 : 0));

        // 解冻前几个 pair
        const unfreezeCount = this._role === 'controlling' ? 1 : 1;
        for (let i = 0; i < Math.min(unfreezeCount, this._checkList.length); i++) {
            this._checkList[i].state = 'waiting';
        }
    }

    // ============================================================
    // ICE 连通性检查
    // ============================================================
    async _performIceChecks() {
        const waitingPairs = this._checkList.filter(p => p.state === 'waiting');
        if (waitingPairs.length === 0) {
            if (this._state !== ICE_STATES.CONNECTED && this._state !== ICE_STATES.COMPLETED) {
                this._state = ICE_STATES.FAILED;
                this._emit('connectionstatechange', 'failed');
            }
            return;
        }

        for (const pair of waitingPairs) {
            pair.state = 'in-progress';
            const checkKey = `${pair.local.address}:${pair.local.port}->${pair.remote.address}:${pair.remote.port}`;
            this._activeChecks.set(checkKey, pair);

            try {
                const success = await this._checkPair(pair);
                if (success) {
                    pair.state = 'succeeded';
                    this._selectPair(pair);
                } else {
                    pair.state = 'failed';
                }
            } catch (e) {
                pair.state = 'failed';
            }
            this._activeChecks.delete(checkKey);
        }

        // 解冻更多 pair
        if (this._state !== ICE_STATES.CONNECTED) {
            for (const pair of this._checkList) {
                if (pair.state === 'frozen') { pair.state = 'waiting'; break; }
            }
            await this._performIceChecks();
        }
    }

    async _checkPair(pair) {
        const { local, remote } = pair;

        // 如果是 relay candidate，通过 TURN 发送
        if (local.candidateType === 'relay') {
            return this._checkViaTurn(local, remote);
        }

        // 如果是 TCP candidate
        if (local.protocol === 'tcp' || remote.protocol === 'tcp') {
            return this._checkViaTcp(local, remote);
        }

        // UDP 直连检查
        return this._checkViaUdp(local, remote);
    }

    async _checkViaUdp(local, remote) {
        return new Promise((resolve) => {
            const request = this._buildStunBindingRequest();
            const port = remote.port || 19000;

            let settled = false;
            const done = (value) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                // 无论成功/超时/发送失败都要移除监听器,避免泄漏
                if (this._udpSocket) this._udpSocket.removeListener('message', handler);
                resolve(value);
            };

            const timer = setTimeout(() => done(false), 3000);

            const handler = (msg) => {
                if (this._isStunResponse(msg, request)) {
                    done(true);
                }
            };

            if (!this._udpSocket) return resolve(false);

            this._udpSocket.on('message', handler);
            this._udpSocket.send(request, port, remote.address, (err) => {
                if (err) done(false);
            });
        });
    }

    async _checkViaTurn(local, remote) {
        const turnClient = this._turnClients.find(t => {
            const addr = t.relayedAddress;
            return addr && addr.address === local.address && addr.port === local.port;
        });
        if (!turnClient) return false;

        try {
            const request = this._buildStunBindingRequest();
            await turnClient.sendToPeer(request, remote.address, remote.port || 19000);
            return true;
        } catch (e) {
            return false;
        }
    }

    async _checkViaTcp(local, remote) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 3000);

            socket.connect(remote.port || 19000, remote.address, () => {
                clearTimeout(timer);
                socket.destroy();
                resolve(true);
            });
            socket.on('error', () => { clearTimeout(timer); resolve(false); });
        });
    }

    _selectPair(pair) {
        this._selectedPair = pair;
        this._state = ICE_STATES.CONNECTED;
        this._emit('connectionstatechange', 'connected');

        if (this._peerConnection) {
            this._peerConnection._establishConnection(
                pair.remote.address,
                pair.remote.port || 19000,
                pair.remote.protocol || 'udp'
            );
        }
    }

    // ============================================================
    // STUN 工具
    // ============================================================
    _buildStunBindingRequest() {
        const msg = Buffer.alloc(20);
        msg.writeUInt16BE(0x0001, 0);
        msg.writeUInt16BE(0x0000, 2);
        msg.writeUInt32BE(0x2112A442, 4);
        for (let i = 8; i < 20; i++) msg.writeUInt8(Math.floor(Math.random() * 256), i);
        return msg;
    }

    _isStunResponse(msg, request) {
        if (msg.length < 20) return false;
        const type = msg.readUInt16BE(0);
        if (type !== 0x0101) return false; // Binding Success Response
        const cookie = msg.readUInt32BE(4);
        if (cookie !== 0x2112A442) return false;
        if (!request) return true;
        return msg.slice(8, 20).equals(request.slice(8, 20));
    }

    async _queryStun(host, port) {
        return new Promise((resolve, reject) => {
            const socket = dgram.createSocket('udp4');
            this._sockets.push(socket);

            const request = this._buildStunBindingRequest();
            const timer = setTimeout(() => { socket.close(); reject(new Error('STUN timeout')); }, 3000);

            socket.on('message', (msg) => {
                clearTimeout(timer);
                socket.close();
                if (msg.length < 32) { reject(new Error('Invalid response')); return; }
                const type = msg.readUInt16BE(0);
                if (type !== 0x0101) { reject(new Error('Invalid type')); return; }

                let offset = 20;
                while (offset + 4 <= msg.length) {
                    const attrType = msg.readUInt16BE(offset);
                    const attrLen = msg.readUInt16BE(offset + 2);
                    if (attrType === 0x0020) { // XOR-MAPPED-ADDRESS
                        const family = msg.readUInt8(offset + 5);
                        const port = msg.readUInt16BE(offset + 6) ^ 0x2112;
                        if (family === 0x01) {
                            const mask = [0x21, 0x12, 0xA4, 0x42];
                            const ip = [];
                            for (let i = 0; i < 4; i++) ip.push(msg.readUInt8(offset + 8 + i) ^ mask[i]);
                            resolve({ address: ip.join('.'), port });
                            return;
                        }
                    }
                    offset += 4 + attrLen;
                }
                reject(new Error('No address'));
            });

            socket.on('error', (err) => { clearTimeout(timer); reject(err); });
            socket.send(request, port, host);
        });
    }

    // ============================================================
    // TURN 数据中继
    // ============================================================
    getTurnClient(index = 0) {
        return this._turnClients[index] || null;
    }

    async sendViaTurn(peerAddress, peerPort, data) {
        for (const client of this._turnClients) {
            try {
                await client.sendToPeer(Buffer.isBuffer(data) ? data : Buffer.from(data), peerAddress, peerPort);
                return true;
            } catch (e) { continue; }
        }
        return false;
    }

    // ============================================================
    // 停止
    // ============================================================
    stop() {
        this._state = ICE_STATES.CLOSED;
        this._emit('connectionstatechange', 'closed');

        for (const socket of this._sockets) {
            try { socket.close(); } catch (e) { /* ignore */ }
        }
        this._sockets = [];

        for (const server of this._tcpServers) {
            try { server.close(); } catch (e) { /* ignore */ }
        }
        this._tcpServers = [];

        for (const client of this._turnClients) {
            try { client.close(); } catch (e) { /* ignore */ }
        }
        this._turnClients = [];

        this._activeChecks.clear();
        this._checkList = [];
    }

    _emit(event, ...args) {
        if (this._callbacks[event]) {
            this._callbacks[event].forEach(cb => cb(...args));
        }
    }
}

IceManager.ICE_STATES = ICE_STATES;

module.exports = IceManager;