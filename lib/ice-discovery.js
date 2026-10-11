// © Vexify 2026 All Rights Reserved.
const dgram = require('dgram');

/**
 * STUN/TURN 服务器自动测速 + 排名
 * 启动时并发测试所有服务器，选最快的 3 个
 */

const DEFAULT_STUN_SERVERS = [
    { urls: 'stun:stun.cloudflare.com:3478', tier: 1 },
    { urls: 'stun:stun.l.google.com:19302', tier: 1 },
    { urls: 'stun:stun1.l.google.com:19302', tier: 1 },
    { urls: 'stun:stun2.l.google.com:19302', tier: 1 },
    { urls: 'stun:stun3.l.google.com:19302', tier: 2 },
    { urls: 'stun:stun4.l.google.com:19302', tier: 2 },
    { urls: 'stun:stun.ekiga.net', tier: 3 },
    { urls: 'stun:stun.fwdnet.net', tier: 3 },
    { urls: 'stun:stun.ideasip.com', tier: 3 },
    { urls: 'stun:stunserver.org', tier: 3 },
    { urls: 'stun:stun.sipgate.net:10000', tier: 3 },
    { urls: 'stun:stun.nextcloud.com:3478', tier: 2 },
    { urls: 'stun:stun.voip.eutelia.it:3478', tier: 3 },
    { urls: 'stun:stun.voipgate.com:3478', tier: 3 },
    { urls: 'stun:stun.voipraider.com:3478', tier: 3 }
];

const DEFAULT_TURN_SERVERS = [
    { urls: 'turn:numb.viagenie.ca', username: 'webrtc@live.com', credential: 'muazkh' },
    { urls: 'turn:turn.anyfirewall.com:443?transport=tcp', username: 'webrtc', credential: 'webrtc' },
    { urls: 'turn:openrelay.metered.ca:80', username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: 'turn:openrelay.metered.ca:443', username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: 'turn:openrelay.metered.ca:443?transport=tcp', username: 'openrelayproject', credential: 'openrelayproject' }
];

class IceServerDiscovery {
    constructor(options = {}) {
        this._options = {
            useDefaultStun: true,
            useDefaultTurn: true,
            customServers: [],
            timeout: 3000,
            concurrency: 8,
            topN: 3,
            ...options
        };
        this._discoveredServers = [];
        this._fastestServers = [];
        this._testResults = new Map();
        this._lastTestTime = 0;
    }

    /**
     * 发现并测速所有 ICE 服务器
     * 返回按延迟排序的可用服务器
     */
    async discover(options = {}) {
        const servers = [];
        if (this._options.useDefaultStun) servers.push(...DEFAULT_STUN_SERVERS);
        if (this._options.useDefaultTurn) servers.push(...DEFAULT_TURN_SERVERS);
        servers.push(...this._options.customServers);

        if (options.test !== false) {
            return await this._speedTest(servers);
        }

        this._discoveredServers = servers;
        return servers;
    }

    /**
     * 并发测速，选最快的 topN
     */
    async _speedTest(servers) {
        const start = Date.now();
        const results = [];
        const pending = [...servers];
        const concurrency = Math.min(this._options.concurrency, pending.length);

        const worker = async () => {
            while (pending.length > 0) {
                const server = pending.shift();
                if (!server) break;
                const result = await this._testServer(server);
                results.push({ ...server, ...result });
            }
        };

        await Promise.all(Array.from({ length: concurrency }, () => worker()));

        // 排序：成功 > 低延迟
        results.sort((a, b) => {
            if (a.success && !b.success) return -1;
            if (!a.success && b.success) return 1;
            if (a.success) return (a.latency || 9999) - (b.latency || 9999);
            return 0;
        });

        this._testResults = new Map(results.map(r => [r.urls, r]));
        this._lastTestTime = Date.now() - start;

        // 最快的作为主力
        this._fastestServers = results.filter(r => r.success).slice(0, this._options.topN);
        this._discoveredServers = results.filter(r => r.success);

        return {
            fastest: this._fastestServers,
            all: results,
            testTime: this._lastTestTime,
            total: results.length,
            success: results.filter(r => r.success).length
        };
    }

    /**
     * 获取最快的 STUN 服务器
     */
    get fastestStunServers() {
        return this._fastestServers.filter(s => s.urls.startsWith('stun:')).slice(0, 3);
    }

    /**
     * 获取最快的 TURN 服务器
     */
    get fastestTurnServers() {
        return this._fastestServers.filter(s => s.urls.startsWith('turn:')).slice(0, 2);
    }

    async _testServer(server) {
        const url = server.urls;
        if (url.startsWith('stun:')) return this._testStunServer(url);
        if (url.startsWith('turn:')) return this._testTurnServer(url);
        return { success: false, latency: null, error: 'Unknown type' };
    }

    async _testStunServer(url) {
        return new Promise((resolve) => {
            const match = url.match(/stun:([^:]+):(\d+)/);
            if (!match) { resolve({ success: false, latency: null, error: 'Invalid URL' }); return; }
            const [, host, port] = match;

            const socket = dgram.createSocket('udp4');
            const msg = Buffer.alloc(20);
            msg.writeUInt16BE(0x0001, 0); // Binding Request
            msg.writeUInt32BE(0x2112A442, 4);

            const start = Date.now();
            let done = false;
            const timer = setTimeout(() => { done = true; socket.close(); resolve({ success: false, latency: null, error: 'Timeout' }); }, this._options.timeout);

            socket.on('message', () => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                socket.close();
                resolve({ success: true, latency: Date.now() - start });
            });
            socket.on('error', (e) => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                socket.close();
                resolve({ success: false, latency: null, error: e.message });
            });
            socket.send(msg, parseInt(port), host, (err) => {
                if (err && !done) { done = true; clearTimeout(timer); socket.close(); resolve({ success: false, latency: null, error: err.message }); }
            });
        });
    }

    async _testTurnServer(url) {
        return new Promise((resolve) => {
            const match = url.match(/turn:([^:]+)(?::(\d+))?/);
            if (!match) { resolve({ success: false, latency: null, error: 'Invalid URL' }); return; }
            const host = match[1];
            const port = parseInt(match[2] || '3478', 10);

            const socket = dgram.createSocket('udp4');
            const msg = Buffer.alloc(20);
            msg.writeUInt16BE(0x0003, 0); // Allocate
            msg.writeUInt32BE(0x2112A442, 4);

            const start = Date.now();
            let done = false;
            const timer = setTimeout(() => { done = true; socket.close(); resolve({ success: false, latency: null, error: 'Timeout' }); }, this._options.timeout);

            socket.on('message', (resp) => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                socket.close();
                const type = resp.readUInt16BE(0);
                // 401/438 也算成功（服务器可达）
                if (type === 0x0103 || type === 0x0113) {
                    resolve({ success: true, latency: Date.now() - start });
                } else {
                    resolve({ success: true, latency: Date.now() - start, needsAuth: true });
                }
            });
            socket.on('error', (e) => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                socket.close();
                resolve({ success: false, latency: null, error: e.message });
            });
            socket.send(msg, port, host, (err) => {
                if (err && !done) { done = true; clearTimeout(timer); socket.close(); resolve({ success: false, latency: null, error: err.message }); }
            });
        });
    }

    get discoveredServers() { return this._discoveredServers; }
    get testResults() { return Object.fromEntries(this._testResults); }
    get lastTestTime() { return this._lastTestTime; }

    getDefaultStunServers() { return [...DEFAULT_STUN_SERVERS]; }
    getDefaultTurnServers() { return [...DEFAULT_TURN_SERVERS]; }
}

module.exports = IceServerDiscovery;
module.exports.DEFAULT_STUN_SERVERS = DEFAULT_STUN_SERVERS;
module.exports.DEFAULT_TURN_SERVERS = DEFAULT_TURN_SERVERS;