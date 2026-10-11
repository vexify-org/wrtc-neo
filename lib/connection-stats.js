class ConnectionStats {
    constructor() {
        this._stats = {
            dataChannels: {
                total: 0,
                open: 0,
                closed: 0
            },
            messages: {
                sent: 0,
                received: 0,
                bytesSent: 0,
                bytesReceived: 0
            },
            ice: {
                candidatesFound: 0,
                candidatesUsed: 0,
                localCandidates: [],
                remoteCandidates: []
            },
            connection: {
                stateChanges: [],
                startTime: null,
                endTime: null,
                duration: 0
            }
        };
        
        this._timers = {};
        this._callbacks = {
            statUpdate: []
        };
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

    start() {
        this._stats.connection.startTime = Date.now();
        this._startPeriodicUpdate();
    }

    stop() {
        this._stats.connection.endTime = Date.now();
        this._stats.connection.duration = this._stats.connection.endTime - this._stats.connection.startTime;
        this._stopPeriodicUpdate();
    }

    addDataChannel(channel) {
        this._stats.dataChannels.total++;
        this._stats.dataChannels.open++;
        this._emit('statUpdate', this._stats);
    }

    removeDataChannel() {
        this._stats.dataChannels.open--;
        this._stats.dataChannels.closed++;
        this._emit('statUpdate', this._stats);
    }

    recordMessageSent(message) {
        this._stats.messages.sent++;
        this._stats.messages.bytesSent += typeof message === 'string' ? message.length : JSON.stringify(message).length;
        this._emit('statUpdate', this._stats);
    }

    recordMessageReceived(message) {
        this._stats.messages.received++;
        this._stats.messages.bytesReceived += typeof message === 'string' ? message.length : JSON.stringify(message).length;
        this._emit('statUpdate', this._stats);
    }

    addLocalCandidate(candidate) {
        this._stats.ice.localCandidates.push(candidate);
        this._stats.ice.candidatesFound++;
        this._emit('statUpdate', this._stats);
    }

    addRemoteCandidate(candidate) {
        this._stats.ice.remoteCandidates.push(candidate);
        this._stats.ice.candidatesFound++;
        this._emit('statUpdate', this._stats);
    }

    useCandidate(candidate) {
        this._stats.ice.candidatesUsed++;
        this._emit('statUpdate', this._stats);
    }

    recordStateChange(state) {
        this._stats.connection.stateChanges.push({
            state,
            timestamp: Date.now()
        });
        this._emit('statUpdate', this._stats);
    }

    get stats() {
        return JSON.parse(JSON.stringify(this._stats));
    }

    get summary() {
        const s = this._stats;
        return {
            dataChannels: {
                total: s.dataChannels.total,
                open: s.dataChannels.open
            },
            messages: {
                total: s.messages.sent + s.messages.received,
                sent: s.messages.sent,
                received: s.messages.received
            },
            bandwidth: {
                sent: this._formatBytes(s.messages.bytesSent),
                received: this._formatBytes(s.messages.bytesReceived)
            },
            ice: {
                candidatesFound: s.ice.candidatesFound,
                candidatesUsed: s.ice.candidatesUsed
            },
            connection: {
                duration: this._formatDuration(s.connection.duration),
                stateChanges: s.connection.stateChanges.length
            }
        };
    }

    getMessageRate() {
        const duration = this._stats.connection.duration || (Date.now() - (this._stats.connection.startTime || Date.now()));
        if (duration <= 0) return 0;
        return ((this._stats.messages.sent + this._stats.messages.received) / duration * 1000).toFixed(2);
    }

    getBandwidth() {
        const duration = this._stats.connection.duration || (Date.now() - (this._stats.connection.startTime || Date.now()));
        if (duration <= 0) return { sent: 0, received: 0 };
        
        return {
            sent: (this._stats.messages.bytesSent / duration * 1000 / 1024).toFixed(2) + ' KB/s',
            received: (this._stats.messages.bytesReceived / duration * 1000 / 1024).toFixed(2) + ' KB/s'
        };
    }

    reset() {
        this._stats = {
            dataChannels: {
                total: 0,
                open: 0,
                closed: 0
            },
            messages: {
                sent: 0,
                received: 0,
                bytesSent: 0,
                bytesReceived: 0
            },
            ice: {
                candidatesFound: 0,
                candidatesUsed: 0,
                localCandidates: [],
                remoteCandidates: []
            },
            connection: {
                stateChanges: [],
                startTime: null,
                endTime: null,
                duration: 0
            }
        };
        this._emit('statUpdate', this._stats);
    }

    toJSON() {
        return {
            ...this._stats,
            summary: this.summary,
            messageRate: this.getMessageRate(),
            bandwidth: this.getBandwidth()
        };
    }

    toString() {
        const s = this.summary;
        return `Connection Stats:
  Data Channels: ${s.dataChannels.open}/${s.dataChannels.total} open
  Messages: ${s.messages.total} (${s.messages.sent} sent, ${s.messages.received} received)
  Bandwidth: ${s.bandwidth.sent} sent, ${s.bandwidth.received} received
  ICE Candidates: ${s.ice.candidatesUsed}/${s.ice.candidatesFound} used
  Connection Duration: ${s.connection.duration}`;
    }

    _startPeriodicUpdate() {
        if (this._timers.update) {
            clearInterval(this._timers.update);
        }
        
        this._timers.update = setInterval(() => {
            this._emit('statUpdate', this._stats);
        }, 1000);
    }

    _stopPeriodicUpdate() {
        if (this._timers.update) {
            clearInterval(this._timers.update);
            this._timers.update = null;
        }
    }

    _formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    _formatDuration(ms) {
        if (ms === 0) return '0ms';
        
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        } else if (seconds > 0) {
            return `${seconds}s`;
        } else {
            return `${ms}ms`;
        }
    }

    _emit(event, ...args) {
        if (this._callbacks[event]) {
            this._callbacks[event].forEach(cb => cb(...args));
        }
    }
}

module.exports = ConnectionStats;