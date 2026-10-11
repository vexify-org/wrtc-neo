const WebSocket = require('ws');

class SignalingClient {
    constructor(url, options = {}) {
        this._url = url;
        this._options = {
            reconnectInterval: options.reconnectInterval || 5000,
            maxReconnectAttempts: options.maxReconnectAttempts || 10,
            pingInterval: options.pingInterval || 30000,
            ...options
        };
        
        this._ws = null;
        this._reconnectAttempts = 0;
        this._pingTimer = null;
        this._reconnectTimer = null;
        this._intentionalClose = false;
        
        this._callbacks = {
            open: [],
            close: [],
            error: [],
            message: [],
            reconnect: []
        };
        
        this._connected = false;
    }

    get connected() {
        return this._connected;
    }

    on(event, callback) {
        if (this._callbacks[event]) {
            this._callbacks[event].push(callback);
        }
    }

    off(event, callback) {
        if (this._callbacks[event]) {
            this._callbacks[event] = this._callbacks[event].filter(cb => cb !== callback);
        }
    }

    connect() {
        // OPEN 或 CONNECTING 中都不得新建 WebSocket,否则会产生双连接/事件串扰
        if (this._ws && (this._ws.readyState === WebSocket.OPEN || this._ws.readyState === WebSocket.CONNECTING)) {
            return;
        }

        this._intentionalClose = false;
        const ws = new WebSocket(this._url, this._options.protocols);
        this._ws = ws;

        // 丢弃过期 socket 的事件,避免旧连接的 close 触发重复重连
        const isStale = () => ws !== this._ws;

        ws.on('open', () => {
            if (isStale()) return;
            this._connected = true;
            this._reconnectAttempts = 0;
            this._startPing();
            this._emit('open');
        });

        ws.on('close', (code, reason) => {
            if (isStale()) return;
            this._connected = false;
            this._stopPing();
            this._emit('close', { code, reason: reason ? reason.toString() : '' });

            if (!this._intentionalClose && code !== 1000 && this._reconnectAttempts < this._options.maxReconnectAttempts) {
                this._scheduleReconnect();
            }
        });

        ws.on('error', (error) => {
            if (isStale()) return;
            this._emit('error', error);
        });

        ws.on('message', (data) => {
            if (isStale()) return;
            let message;
            try {
                message = JSON.parse(data.toString());
            } catch {
                message = data.toString();
            }
            this._emit('message', message);
        });
    }

    disconnect() {
        this._intentionalClose = true;
        if (this._reconnectTimer) {
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
        }
        this._stopPing();

        if (this._ws) {
            const ws = this._ws;
            this._ws = null;
            // 先置空再 close,配合 isStale 屏蔽后续事件
            try {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close(1000, 'Client disconnect');
                } else if (ws.readyState === WebSocket.CONNECTING) {
                    // 握手中直接终止,避免 close() 排队等待 open
                    ws.terminate();
                }
            } catch (e) { /* ignore */ }
        }

        this._connected = false;
        this._reconnectAttempts = 0;
    }

    send(data) {
        if (!this._connected || !this._ws) {
            throw new Error('Not connected to signaling server');
        }
        
        const payload = typeof data === 'string' ? data : JSON.stringify(data);
        this._ws.send(payload);
    }

    sendOffer(peerId, offer) {
        this.send({
            type: 'offer',
            from: this._options.peerId,
            to: peerId,
            data: offer
        });
    }

    sendAnswer(peerId, answer) {
        this.send({
            type: 'answer',
            from: this._options.peerId,
            to: peerId,
            data: answer
        });
    }

    sendIceCandidate(peerId, candidate) {
        this.send({
            type: 'ice_candidate',
            from: this._options.peerId,
            to: peerId,
            data: candidate
        });
    }

    sendKeepAlive() {
        this.send({ type: 'keep_alive' });
    }

    _startPing() {
        if (this._pingTimer) {
            clearInterval(this._pingTimer);
        }
        
        this._pingTimer = setInterval(() => {
            if (this._connected && this._ws) {
                this.sendKeepAlive();
            }
        }, this._options.pingInterval);
    }

    _stopPing() {
        if (this._pingTimer) {
            clearInterval(this._pingTimer);
            this._pingTimer = null;
        }
    }

    _scheduleReconnect() {
        if (this._reconnectTimer) {
            clearTimeout(this._reconnectTimer);
        }
        
        this._reconnectAttempts++;
        const delay = this._options.reconnectInterval * this._reconnectAttempts;
        
        this._reconnectTimer = setTimeout(() => {
            this._reconnectTimer = null;
            if (this._intentionalClose) return;
            this._emit('reconnect', { attempt: this._reconnectAttempts });
            // 丢弃旧 socket,重新建连
            if (this._ws) {
                const old = this._ws;
                this._ws = null;
                try { old.terminate(); } catch (e) { /* ignore */ }
            }
            this.connect();
        }, delay);
    }

    _emit(event, ...args) {
        if (this._callbacks[event]) {
            this._callbacks[event].forEach(cb => cb(...args));
        }
        if (this[`on${event}`]) {
            this[`on${event}`](...args);
        }
    }
}

module.exports = SignalingClient;