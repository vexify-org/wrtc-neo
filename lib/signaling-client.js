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
        if (this._ws && this._ws.readyState === WebSocket.OPEN) {
            return;
        }

        this._ws = new WebSocket(this._url, this._options.protocols);

        this._ws.on('open', () => {
            this._connected = true;
            this._reconnectAttempts = 0;
            this._startPing();
            this._emit('open');
        });

        this._ws.on('close', (code, reason) => {
            this._connected = false;
            this._stopPing();
            this._emit('close', { code, reason: reason.toString() });
            
            if (code !== 1000 && this._reconnectAttempts < this._options.maxReconnectAttempts) {
                this._scheduleReconnect();
            }
        });

        this._ws.on('error', (error) => {
            this._emit('error', error);
        });

        this._ws.on('message', (data) => {
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
        if (this._reconnectTimer) {
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
        }
        this._stopPing();
        
        if (this._ws) {
            this._ws.close(1000, 'Client disconnect');
            this._ws = null;
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
            this._emit('reconnect', { attempt: this._reconnectAttempts });
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