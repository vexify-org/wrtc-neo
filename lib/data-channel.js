const dgram = require('dgram');
const net = require('net');

class RTCDataChannel {
    constructor(peerConnection, label, options = {}) {
        this.peerConnection = peerConnection;
        this.label = label || 'wrtc-neo';
        this.options = {
            ordered: options.ordered !== undefined ? options.ordered : true,
            maxRetransmitTime: options.maxRetransmitTime || 0,
            maxRetransmits: options.maxRetransmits || 0,
            protocol: options.protocol || '',
            negotiated: options.negotiated || false,
            id: options.id || null
        };
        
        this.readyState = 'connecting';
        this.bufferedAmount = 0;
        this.bufferedAmountLowThreshold = 0;
        
        this._callbacks = {
            open: [],
            close: [],
            message: [],
            error: [],
            bufferedamountlow: []
        };
        
        this._socket = null;
        this._remoteAddress = null;
        this._remotePort = null;
        this._messageQueue = [];
        this._queueProcessing = false;
    }

    get ordered() { return this.options.ordered; }
    get maxRetransmitTime() { return this.options.maxRetransmitTime; }
    get maxRetransmits() { return this.options.maxRetransmits; }
    get protocol() { return this.options.protocol; }
    get negotiated() { return this.options.negotiated; }
    get id() { return this.options.id; }

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

    send(data) {
        if (this.readyState !== 'open') {
            throw new Error('DataChannel is not open');
        }
        
        const message = typeof data === 'string' ? data : JSON.stringify(data);
        
        if (this._socket) {
            if (this._socket.type === 'udp4' || this._socket.type === 'udp6') {
                const buffer = Buffer.from(message);
                this._socket.send(buffer, this._remotePort, this._remoteAddress, (err) => {
                    if (err) {
                        this._emit('error', err);
                    }
                });
            } else {
                this._socket.write(message + '\n');
            }
        }
        
        this.bufferedAmount += message.length;
        if (this.bufferedAmount < this.bufferedAmountLowThreshold) {
            this._emit('bufferedamountlow');
        }
    }

    close() {
        if (this.readyState === 'closed') return;
        
        this.readyState = 'closing';
        
        if (this._socket) {
            this._socket.close();
            this._socket = null;
        }
        
        this.readyState = 'closed';
        this._emit('close');
    }

    _openSocket(address, port, protocol = 'udp') {
        this._remoteAddress = address;
        this._remotePort = port;
        
        if (protocol === 'udp') {
            this._socket = dgram.createSocket(address.includes(':') ? 'udp6' : 'udp4');
            
            this._socket.on('message', (msg) => {
                const data = msg.toString();
                this._emit('message', { data });
            });
            
            this._socket.on('error', (err) => {
                this._emit('error', err);
            });
            
            this._socket.on('close', () => {
                if (this.readyState !== 'closed') {
                    this.readyState = 'closed';
                    this._emit('close');
                }
            });
            
            this._socket.bind(() => {
                this.readyState = 'open';
                this._emit('open');
            });
        } else {
            this._socket = new net.Socket();
            
            this._socket.connect(port, address, () => {
                this.readyState = 'open';
                this._emit('open');
            });
            
            this._socket.on('data', (data) => {
                const message = data.toString().trim();
                if (message) {
                    this._emit('message', { data: message });
                }
            });
            
            this._socket.on('error', (err) => {
                this._emit('error', err);
            });
            
            this._socket.on('close', () => {
                if (this.readyState !== 'closed') {
                    this.readyState = 'closed';
                    this._emit('close');
                }
            });
        }
    }

    _acceptConnection(socket) {
        this._socket = socket;
        this.readyState = 'open';
        
        this._socket.on('data', (data) => {
            const message = data.toString().trim();
            if (message) {
                this._emit('message', { data: message });
            }
        });
        
        this._socket.on('error', (err) => {
            this._emit('error', err);
        });
        
        this._socket.on('close', () => {
            if (this.readyState !== 'closed') {
                this.readyState = 'closed';
                this._emit('close');
            }
        });
        
        this._emit('open');
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

module.exports = RTCDataChannel;