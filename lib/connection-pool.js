// © Vexify 2026 All Rights Reserved.
const crypto = require('crypto');

/**
 * 连接池 v2 — 自动重连 + 指数退避 + 连接质量 + 断线消息缓存
 */

class ConnectionQuality {
    constructor() {
        this._latencySamples = [];
        this._packetLoss = 0;
        this._totalSent = 0;
        this._totalLost = 0;
        this._bandwidth = 0;
        this._lastUpdate = Date.now();
    }

    recordLatency(ms) {
        this._latencySamples.push(ms);
        if (this._latencySamples.length > 50) this._latencySamples.shift();
    }

    recordPacketLoss(lost) {
        this._totalSent++;
        if (lost) this._totalLost++;
        this._packetLoss = this._totalSent > 0 ? this._totalLost / this._totalSent : 0;
    }

    get avgLatency() {
        if (this._latencySamples.length === 0) return 0;
        return this._latencySamples.reduce((a, b) => a + b, 0) / this._latencySamples.length;
    }

    get minLatency() { return this._latencySamples.length > 0 ? Math.min(...this._latencySamples) : 0; }
    get maxLatency() { return this._latencySamples.length > 0 ? Math.max(...this._latencySamples) : 0; }
    get packetLoss() { return this._packetLoss; }
    get jitter() {
        if (this._latencySamples.length < 2) return 0;
        let sum = 0;
        for (let i = 1; i < this._latencySamples.length; i++) {
            sum += Math.abs(this._latencySamples[i] - this._latencySamples[i - 1]);
        }
        return sum / (this._latencySamples.length - 1);
    }

    get score() {
        // 综合质量评分 0-100，越高越好
        if (this._latencySamples.length === 0) return 0;
        const latencyScore = Math.max(0, 100 - this.avgLatency);
        const lossScore = (1 - this.packetLoss) * 100;
        const jitterScore = Math.max(0, 100 - this.jitter * 2);
        return Math.round((latencyScore * 0.4 + lossScore * 0.4 + jitterScore * 0.2));
    }

    get summary() {
        return {
            avgLatency: Math.round(this.avgLatency),
            minLatency: this.minLatency,
            maxLatency: this.maxLatency,
            packetLoss: (this.packetLoss * 100).toFixed(1) + '%',
            jitter: Math.round(this.jitter),
            score: this.score
        };
    }
}

class ReconnectBuffer {
    constructor(options = {}) {
        this._maxSize = options.maxSize || 1024 * 1024; // 1 MB
        this._maxMessages = options.maxMessages || 1000;
        this._buffer = [];
        this._size = 0;
    }

    push(message) {
        // JSON.stringify 在循环引用/BigInt 时会抛异常，不能让缓存写入炸掉调用方
        let msgSize;
        if (Buffer.isBuffer(message)) {
            msgSize = message.length;
        } else if (typeof message === 'string') {
            msgSize = Buffer.byteLength(message);
        } else {
            try {
                msgSize = Buffer.byteLength(JSON.stringify(message) || '');
            } catch (e) {
                msgSize = 0;
            }
        }
        // 单条消息超过总容量时不缓存（否则会把其它消息全部挤掉）
        if (msgSize > this._maxSize) return false;

        while (this._size + msgSize > this._maxSize || this._buffer.length >= this._maxMessages) {
            const evicted = this._buffer.shift(); // 丢弃最旧的
            if (!evicted) break;
            this._size -= evicted.size;
        }
        this._buffer.push({ message, timestamp: Date.now(), size: msgSize });
        this._size += msgSize;
        return true;
    }

    drain() {
        const messages = [...this._buffer];
        this._buffer = [];
        this._size = 0;
        return messages;
    }

    get count() { return this._buffer.length; }
    get size() { return this._size; }
}

class ConnectionPool {
    constructor(options = {}) {
        this.maxConnections = Number.isInteger(options.maxConnections) && options.maxConnections > 0
            ? options.maxConnections : 10;
        this.minConnections = Number.isInteger(options.minConnections) && options.minConnections >= 0
            ? Math.min(options.minConnections, this.maxConnections) : Math.min(2, this.maxConnections);
        this.connections = new Map();
        this.pendingConnections = new Set();
        this._listener = {};
        this._autoReconnect = options.autoReconnect !== false;
        this._baseDelay = options.reconnectDelay || 1000;
        this._maxDelay = options.maxReconnectDelay || 30000;
        this._maxAttempts = options.reconnectAttempts || 10;
        this._connectionFactory = options.connectionFactory || null;
        this._quality = new Map(); // peerId -> ConnectionQuality
        this._messageBuffers = new Map(); // peerId -> MessageBuffer
        this._reconnectTimers = new Map();
        this._pingTimers = new Map();
        this._pingInterval = options.pingInterval || 5000;
        // 主动关闭中的 peer,其 close 事件不应触发自动重连
        this._intentionalClose = new Set();
    }

    setConnectionFactory(factory) {
        this._connectionFactory = factory;
    }

    async getConnection(peerId) {
        if (typeof peerId !== 'string' || !peerId || peerId.length > 256) {
            throw new TypeError('Invalid peerId');
        }
        if (this.connections.has(peerId)) return this.connections.get(peerId);
        if (this.connections.size >= this.maxConnections) this._cleanupOldConnections();
        if (this.pendingConnections.has(peerId)) return this._waitForConnection(peerId);
        return this._createConnection(peerId);
    }

    async _createConnection(peerId) {
        this.pendingConnections.add(peerId);
        try {
            if (!this._connectionFactory) throw new Error('No connection factory set');
            if (this.connections.has(peerId)) {
                // 并发重连时已有连接，直接复用，避免同一 peer 出现两条连接
                this.pendingConnections.delete(peerId);
                return this.connections.get(peerId);
            }
            const connection = await this._connectionFactory(peerId);
            if (!connection || typeof connection.on !== 'function') {
                throw new TypeError('connection factory must return an EventEmitter-like connection');
            }
            this.connections.set(peerId, connection);
            this.pendingConnections.delete(peerId);
            this._quality.set(peerId, new ConnectionQuality());
            if (!this._messageBuffers.has(peerId)) this._messageBuffers.set(peerId, new ReconnectBuffer());

            try {
                connection.on('close', () => this._handleConnectionClose(peerId));
                connection.on('error', () => this._handleConnectionClose(peerId));
            } catch (e) {
                // 事件绑定失败时回滚，避免 map 里留下不可用的连接
                this.connections.delete(peerId);
                try { connection.close && connection.close(); } catch (err) { /* ignore */ }
                throw e;
            }

            this._emit('connectionCreated', { peerId, connection });

            // 开始质量监控
            this._startPing(peerId, connection);

            return connection;
        } catch (error) {
            this.pendingConnections.delete(peerId);
            this._emit('connectionError', { peerId, error });
            throw error;
        }
    }

    async _waitForConnection(peerId) {
        return new Promise((resolve, reject) => {
            let check = null;
            const timeout = setTimeout(() => {
                // reject 时必须清掉轮询 interval,否则定时器泄漏、进程无法退出
                if (check) clearInterval(check);
                reject(new Error('Connection timeout'));
            }, 30000);
            check = setInterval(() => {
                if (this.connections.has(peerId)) { clearInterval(check); clearTimeout(timeout); resolve(this.connections.get(peerId)); }
                else if (!this.pendingConnections.has(peerId)) { clearInterval(check); clearTimeout(timeout); reject(new Error('Connection failed')); }
            }, 100);
        });
    }

    _handleConnectionClose(peerId) {
        this.connections.delete(peerId);
        this._stopPing(peerId);
        this._emit('connectionClosed', { peerId });
        // 主动淘汰/关闭的连接不重连
        if (this._intentionalClose.has(peerId)) {
            this._intentionalClose.delete(peerId);
            return;
        }
        if (this._autoReconnect) this._scheduleReconnect(peerId);
    }

    // ============================================================
    // 指数退避重连
    // ============================================================
    async _scheduleReconnect(peerId) {
        if (this._reconnectTimers.has(peerId)) return;

        // 重试次数上限保护（防止配置成 Infinity/巨大值导致无限重连）
        const maxAttempts = Math.min(
            Math.max(Number.isFinite(Number(this._maxAttempts)) ? Math.floor(Number(this._maxAttempts)) : 10, 1),
            100
        );
        const maxDelay = Math.max(Number(this._maxDelay) || 30000, 1000);

        // 用状态对象代替裸 timer id：既要能取消，也要能唤醒等待中的 Promise
        const state = { cancelled: false, timer: null, wake: null };
        this._reconnectTimers.set(peerId, state);

        const sleep = (ms) => new Promise((resolve) => {
            state.wake = resolve;
            state.timer = setTimeout(resolve, ms);
        });

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            if (state.cancelled || this.connections.has(peerId)) {
                this._reconnectTimers.delete(peerId);
                return;
            }

            const delay = Math.min(this._baseDelay * Math.pow(2, attempt - 1), maxDelay);
            const jitter = delay * (0.5 + Math.random() * 0.5); // 50%-100% jitter

            this._emit('reconnecting', { peerId, attempt, delay: Math.round(jitter) });

            await sleep(jitter);
            if (state.cancelled) {
                this._reconnectTimers.delete(peerId);
                return;
            }

            if (this.connections.has(peerId)) {
                this._reconnectTimers.delete(peerId);
                return;
            }

            try {
                await this._createConnection(peerId);
                this._reconnectTimers.delete(peerId);
                this._emit('reconnected', { peerId, attempt });

                // 重连成功后补发缓存消息
                const buffer = this._messageBuffers.get(peerId);
                if (buffer && buffer.count > 0) {
                    const messages = buffer.drain();
                    this._emit('deliverBuffered', { peerId, messages });
                }
                return;
            } catch (e) {
                this._emit('reconnectFailed', { peerId, attempt, error: e.message });
            }
        }

        this._reconnectTimers.delete(peerId);
        this._emit('reconnectExhausted', { peerId });
    }

    _cancelReconnect(peerId) {
        const state = this._reconnectTimers.get(peerId);
        if (!state) return;
        state.cancelled = true;
        if (state.timer) clearTimeout(state.timer);
        if (typeof state.wake === 'function') state.wake();
        this._reconnectTimers.delete(peerId);
    }

    // ============================================================
    // 连接质量监控（Ping 测延迟）
    // ============================================================
    _startPing(peerId, connection) {
        const timer = setInterval(() => {
            if (!this.connections.has(peerId)) { clearInterval(timer); return; }
            const start = Date.now();
            const pingId = crypto.randomBytes(4).toString('hex');

            // 发送 ping
            if (connection.send) {
                const sent = connection.send(JSON.stringify({ type: 'ping', id: pingId, ts: start }));
                // 只有显式返回 false 才是丢包;很多传输层 send() 无返回值(undefined)
                if (sent === false) {
                    this._quality.get(peerId)?.recordPacketLoss(true);
                    return;
                }
            }

            // 等 pong 或超时
            const removeHandler = () => {
                if (typeof connection.off === 'function') {
                    try { connection.off('message', onPong); } catch (e) { /* ignore */ }
                } else if (typeof connection.removeListener === 'function') {
                    try { connection.removeListener('message', onPong); } catch (e) { /* ignore */ }
                }
            };

            const timeout = setTimeout(() => {
                this._quality.get(peerId)?.recordPacketLoss(true);
                removeHandler();
            }, 2000);

            const onPong = (msg) => {
                try {
                    const data = JSON.parse(msg);
                    if (data.type === 'pong' && data.id === pingId) {
                        clearTimeout(timeout);
                        const latency = Date.now() - start;
                        this._quality.get(peerId)?.recordLatency(latency);
                        this._quality.get(peerId)?.recordPacketLoss(false);
                        removeHandler();
                    }
                } catch (e) { /* ignore */ }
            };

            if (typeof connection.on === 'function') {
                connection.on('message', onPong);
            }
        }, this._pingInterval);

        this._pingTimers.set(peerId, timer);
    }

    _stopPing(peerId) {
        const timer = this._pingTimers.get(peerId);
        if (timer) { clearInterval(timer); this._pingTimers.delete(peerId); }
    }

    // ============================================================
    // 消息缓冲
    // ============================================================
    bufferMessage(peerId, message) {
        if (!this._messageBuffers.has(peerId)) {
            this._messageBuffers.set(peerId, new ReconnectBuffer());
        }
        this._messageBuffers.get(peerId).push(message);
    }

    drainBuffer(peerId) {
        const buffer = this._messageBuffers.get(peerId);
        return buffer ? buffer.drain() : [];
    }

    getQuality(peerId) {
        const q = this._quality.get(peerId);
        return q ? q.summary : null;
    }

    getAllQuality() {
        const result = {};
        for (const [peerId, q] of this._quality) {
            result[peerId] = q.summary;
        }
        return result;
    }

    // ============================================================
    // 管理
    // ============================================================
    _cleanupOldConnections() {
        const sorted = [...this.connections.entries()].sort((a, b) => {
            return (a[1].lastUsed || 0) - (b[1].lastUsed || 0);
        });
        // 至少腾出一个名额，且不能因为 minConnections 配置异常而误删所有连接
        const removeCount = Math.max(
            sorted.length - this.minConnections,
            sorted.length >= this.maxConnections ? 1 : 0
        );
        const toRemove = sorted.slice(0, Math.min(removeCount, sorted.length));
        for (const [peerId, connection] of toRemove) {
            // 标记主动关闭,避免 close 事件误触发自动重连
            this._intentionalClose.add(peerId);
            connection.close();
            this.connections.delete(peerId);
            this._stopPing(peerId);
        }
    }

    releaseConnection(peerId) {
        if (this.connections.has(peerId)) {
            this.connections.get(peerId).lastUsed = Date.now();
        }
    }

    closeConnection(peerId) {
        this._stopPing(peerId);
        this._cancelReconnect(peerId);
        if (this.connections.has(peerId)) {
            // 主动关闭: 屏蔽 close 事件引发的自动重连
            this._intentionalClose.add(peerId);
            this.connections.get(peerId).close();
            this.connections.delete(peerId);
            this._emit('connectionClosed', { peerId });
        }
    }

    closeAll() {
        // 阻止所有 close 事件触发重连
        this._autoReconnect = false;
        for (const [peerId, connection] of this.connections) {
            this._intentionalClose.add(peerId);
            connection.close();
        }
        this.connections.clear();
        for (const timer of this._pingTimers.values()) clearInterval(timer);
        this._pingTimers.clear();
        this._reconnectTimers.forEach((state) => {
            if (state && typeof state === 'object') {
                state.cancelled = true;
                if (state.timer) clearTimeout(state.timer);
                if (typeof state.wake === 'function') state.wake();
            } else {
                clearTimeout(state);
            }
        });
        this._reconnectTimers.clear();
        this.pendingConnections.clear();
        this._quality.clear();
        this._messageBuffers.clear();
        this._emit('poolClosed');
    }

    getStats() {
        return {
            activeConnections: this.connections.size,
            pendingConnections: this.pendingConnections.size,
            maxConnections: this.maxConnections,
            minConnections: this.minConnections,
            bufferedMessages: [...this._messageBuffers.values()].reduce((s, b) => s + b.count, 0),
            quality: this.getAllQuality()
        };
    }

    on(event, callback) { if (!this._listener[event]) this._listener[event] = []; this._listener[event].push(callback); }
    off(event, callback) { if (this._listener[event]) this._listener[event] = this._listener[event].filter(cb => cb !== callback); }
    _emit(event, data) {
        if (this._listener[event]) for (const cb of this._listener[event]) { try { cb(data); } catch (e) { console.error('ConnectionPool event error:', e); } }
    }
}

module.exports = { ConnectionPool, ConnectionQuality, ReconnectBuffer };