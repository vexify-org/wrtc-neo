class ReliableChannel {
    constructor(dataChannel, options = {}) {
        this._channel = dataChannel;
        this._options = {
            maxRetries: options.maxRetries || 5,
            retryDelay: options.retryDelay || 1000,
            ackTimeout: options.ackTimeout || 5000,
            maxQueueSize: options.maxQueueSize || 1000,
            enableAck: options.enableAck !== false,
            ...options
        };
        
        this._sequenceNumber = 0;
        this._pendingMessages = new Map();
        this._receivedMessages = new Set();
        // 限制去重集合大小,防止长时间运行内存无上限增长
        this._maxDedupSize = options.maxDedupSize || 10000;
        this._messageQueue = [];
        this._isOpen = false;
        this._closed = false;
        this._listener = {};
        
        this._setupChannel();
    }

    _setupChannel() {
        this._channel.on('open', () => {
            this._isOpen = true;
            this._processQueue();
            this._emit('open');
        });

        this._channel.on('close', () => {
            this._isOpen = false;
            this._emit('close');
        });

        this._channel.on('error', (error) => {
            this._emit('error', error);
        });

        this._channel.on('message', (event) => {
            this._handleMessage(event.data);
        });
    }

    _handleMessage(data) {
        try {
            const message = JSON.parse(data);
            
            if (message.type === 'ack') {
                this._handleAck(message.sequence);
            } else if (message.type === 'data') {
                if (!this._receivedMessages.has(message.sequence)) {
                    this._receivedMessages.add(message.sequence);
                    // 超过上限时淘汰最旧的序号(Set 保持插入序)
                    while (this._receivedMessages.size > this._maxDedupSize) {
                        const oldest = this._receivedMessages.values().next().value;
                        this._receivedMessages.delete(oldest);
                    }
                    
                    if (this._options.enableAck) {
                        this._sendAck(message.sequence);
                    }
                    
                    this._emit('message', message.data);
                }
            }
        } catch (error) {
            this._emit('error', error);
        }
    }

    _handleAck(sequence) {
        const pending = this._pendingMessages.get(sequence);
        if (pending) {
            clearTimeout(pending.timeout);
            this._pendingMessages.delete(sequence);
            this._emit('ack', sequence);
        }
    }

    _sendAck(sequence) {
        if (!this._isOpen) return;
        
        const ack = JSON.stringify({
            type: 'ack',
            sequence
        });
        
        this._channel.send(ack);
    }

    send(data, options = {}) {
        const sequence = this._sequenceNumber++;
        const message = JSON.stringify({
            type: 'data',
            sequence,
            data,
            timestamp: Date.now(),
            priority: options.priority || 'normal'
        });

        if (!this._isOpen) {
            if (this._messageQueue.length < this._options.maxQueueSize) {
                this._messageQueue.push({ message, sequence, options });
            } else {
                this._emit('error', new Error('Message queue full'));
            }
            return;
        }

        this._channel.send(message);

        if (this._options.enableAck) {
            this._pendingMessages.set(sequence, {
                message,
                attempts: 0,
                timeout: setTimeout(() => {
                    this._retryMessage(sequence);
                }, this._options.ackTimeout)
            });
        }
    }

    _retryMessage(sequence) {
        const pending = this._pendingMessages.get(sequence);
        if (!pending) return;

        pending.attempts++;

        if (pending.attempts >= this._options.maxRetries) {
            this._pendingMessages.delete(sequence);
            this._emit('retryExhausted', { sequence, attempts: pending.attempts });
            return;
        }

        if (this._closed) {
            // 已关闭: 不再重试
            this._pendingMessages.delete(sequence);
            return;
        }

        if (!this._isOpen) {
            // 信道暂时关闭: 消息重新排队,等 open 后继续发送,
            // 不能静默丢弃(旧实现会丢 pending 消息)
            this._pendingMessages.delete(sequence);
            if (this._messageQueue.length < this._options.maxQueueSize) {
                this._messageQueue.unshift({ message: pending.message, sequence, options: {} });
            } else {
                this._emit('retryExhausted', { sequence, attempts: pending.attempts });
            }
            return;
        }

        this._channel.send(pending.message);
        pending.timeout = setTimeout(() => {
            this._retryMessage(sequence);
        }, this._options.ackTimeout * pending.attempts);
    }

    _processQueue() {
        while (this._messageQueue.length > 0 && this._isOpen) {
            const item = this._messageQueue.shift();
            this._channel.send(item.message);
            
            if (this._options.enableAck) {
                this._pendingMessages.set(item.sequence, {
                    message: item.message,
                    attempts: 0,
                    timeout: setTimeout(() => {
                        this._retryMessage(item.sequence);
                    }, this._options.ackTimeout)
                });
            }
        }
    }

    close() {
        this._closed = true;
        for (const pending of this._pendingMessages.values()) {
            clearTimeout(pending.timeout);
        }
        this._pendingMessages.clear();
        this._messageQueue = [];
        this._channel.close();
    }

    get bufferedAmount() {
        return this._channel.bufferedAmount;
    }

    get readyState() {
        return this._channel.readyState;
    }

    on(event, callback) {
        if (!this._listener[event]) {
            this._listener[event] = [];
        }
        this._listener[event].push(callback);
    }

    off(event, callback) {
        if (this._listener[event]) {
            this._listener[event] = this._listener[event].filter(cb => cb !== callback);
        }
    }

    _emit(event, data) {
        if (this._listener[event]) {
            for (const callback of this._listener[event]) {
                try {
                    callback(data);
                } catch (error) {
                    console.error('ReliableChannel event error:', error);
                }
            }
        }
    }
}

class MessageBuffer {
    constructor(options = {}) {
        this._maxSize = options.maxSize || 1024 * 1024;
        this._buffer = [];
        this._totalSize = 0;
        this._listener = {};
    }

    add(message) {
        const size = JSON.stringify(message).length;
        
        while (this._totalSize + size > this._maxSize && this._buffer.length > 0) {
            const removed = this._buffer.shift();
            this._totalSize -= JSON.stringify(removed).length;
            this._emit('evicted', removed);
        }
        
        this._buffer.push(message);
        this._totalSize += size;

        // highWaterMark 按字节量判断(旧实现用条数比 maxSize/2,单位不一致)
        if (this._totalSize >= this._maxSize / 2) {
            this._emit('highWaterMark', this._totalSize);
        }
    }

    get(size = null) {
        if (size === null) {
            const result = [...this._buffer];
            this._buffer = [];
            this._totalSize = 0;
            return result;
        }
        
        const result = this._buffer.slice(0, size);
        this._buffer = this._buffer.slice(size);
        
        for (const msg of result) {
            this._totalSize -= JSON.stringify(msg).length;
        }
        
        return result;
    }

    peek(size = null) {
        if (size === null) {
            return [...this._buffer];
        }
        return this._buffer.slice(0, size);
    }

    clear() {
        this._buffer = [];
        this._totalSize = 0;
    }

    get length() {
        return this._buffer.length;
    }

    get size() {
        return this._totalSize;
    }

    on(event, callback) {
        if (!this._listener[event]) {
            this._listener[event] = [];
        }
        this._listener[event].push(callback);
    }

    off(event, callback) {
        if (this._listener[event]) {
            this._listener[event] = this._listener[event].filter(cb => cb !== callback);
        }
    }

    _emit(event, data) {
        if (this._listener[event]) {
            for (const callback of this._listener[event]) {
                try {
                    callback(data);
                } catch (error) {
                    console.error('MessageBuffer event error:', error);
                }
            }
        }
    }
}

module.exports = {
    ReliableChannel,
    MessageBuffer
};