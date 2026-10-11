// © Vexify 2026 All Rights Reserved.
const crypto = require('crypto');
const dgram = require('dgram');
const { EventEmitter } = require('events');

/**
 * 网络拓扑管理 — Mesh + 星型 + DHT + 多跳中继
 *
 * 特性：
 * - Mesh 网状网络：房间内所有节点两两互连
 * - 星型拓扑：弱网节点通过强节点（超级节点）转发
 * - DHT 分布式哈希表：Kademlia 风格，不依赖中心信令服务器
 * - 多跳中继：两个直连连不上的节点通过第三方中转
 */

const K_BUCKET_SIZE = 20;
const ALPHA = 3; // Kademlia 并发查询数
const PING_INTERVAL = 60000; // DHT ping 间隔
const REFRESH_INTERVAL = 3600000; // 桶刷新间隔
const DHT_PORT = 6881; // DHT 默认端口

// ============================================================
// DHT 节点 ID（160-bit SHA-1）
// ============================================================
class NodeId {
    constructor(id) {
        if (id instanceof Buffer && id.length === 20) {
            this._buffer = id;
        } else if (typeof id === 'string' && id.length === 40) {
            this._buffer = Buffer.from(id, 'hex');
        } else {
            this._buffer = crypto.randomBytes(20);
        }
    }

    get buffer() { return this._buffer; }
    get hex() { return this._buffer.toString('hex'); }
    get short() { return this._buffer.toString('hex').substring(0, 12); }

    /**
     * XOR 距离
     */
    distance(other) {
        const buf = Buffer.alloc(20);
        for (let i = 0; i < 20; i++) {
            buf[i] = this._buffer[i] ^ other._buffer[i];
        }
        return buf;
    }

    /**
     * 距离的前导零位数（用于确定 k-bucket 索引）
     */
    distanceBits(other) {
        const dist = this.distance(other);
        let bits = 0;
        for (let i = 0; i < 20; i++) {
            if (dist[i] === 0) {
                bits += 8;
            } else {
                let b = dist[i];
                while (b < 128) { bits++; b <<= 1; }
                break;
            }
        }
        return bits;
    }

    equals(other) {
        return this._buffer.equals(other._buffer);
    }

    static fromHex(hex) { return new NodeId(hex); }
    static random() { return new NodeId(); }
}

// ============================================================
// Kademlia DHT 路由表
// ============================================================
class RoutingTable {
    constructor(nodeId) {
        this._nodeId = nodeId;
        this._buckets = []; // 160 个桶，每个最多 K_BUCKET_SIZE 个节点
        for (let i = 0; i < 160; i++) {
            this._buckets.push([]);
        }
    }

    /**
     * 添加节点到路由表
     */
    addNode(node) {
        const bucketIdx = this._nodeId.distanceBits(node.id);
        if (bucketIdx >= 160) return false; // 自己

        const bucket = this._buckets[bucketIdx];

        // 检查是否已存在
        const existing = bucket.find(n => n.id.equals(node.id));
        if (existing) {
            // 移到末尾（最近使用）
            bucket.splice(bucket.indexOf(existing), 1);
            bucket.push(node);
            return true;
        }

        if (bucket.length < K_BUCKET_SIZE) {
            bucket.push(node);
            return true;
        }

        // 桶已满，ping 最旧的节点
        return false;
    }

    /**
     * 移除节点
     */
    removeNode(nodeId) {
        for (const bucket of this._buckets) {
            const idx = bucket.findIndex(n => n.id.equals(nodeId));
            if (idx !== -1) {
                bucket.splice(idx, 1);
                return true;
            }
        }
        return false;
    }

    /**
     * 查找距离目标最近的 K 个节点
     */
    findClosest(targetId, k = K_BUCKET_SIZE) {
        const allNodes = [];
        for (const bucket of this._buckets) {
            for (const node of bucket) {
                allNodes.push(node);
            }
        }
        allNodes.sort((a, b) => {
            const da = targetId.distance(a.id);
            const db = targetId.distance(b.id);
            return Buffer.compare(da, db);
        });
        return allNodes.slice(0, k);
    }

    /**
     * 获取所有节点
     */
    getAllNodes() {
        const all = [];
        for (const bucket of this._buckets) {
            for (const node of bucket) all.push(node);
        }
        return all;
    }

    get size() {
        let count = 0;
        for (const bucket of this._buckets) count += bucket.length;
        return count;
    }

    getStats() {
        const buckets = this._buckets.map((b, i) => ({ index: i, size: b.length })).filter(b => b.size > 0);
        return { totalNodes: this.size, buckets: buckets.length, bucketDetails: buckets };
    }
}

// ============================================================
// 网络拓扑管理器
// ============================================================
class NetworkTopology extends EventEmitter {
    constructor(options = {}) {
        super();
        this._options = {
            nodeId: options.nodeId || NodeId.random(),
            dhtPort: options.dhtPort || DHT_PORT,
            bootstrapNodes: options.bootstrapNodes || [],
            enableDht: options.enableDht !== false,
            enableMesh: options.enableMesh !== false,
            enableStar: options.enableStar !== false,
            enableRelay: options.enableRelay !== false,
            ...options
        };

        this._nodeId = this._options.nodeId;
        this._routingTable = new RoutingTable(this._nodeId);
        this._peers = new Map(); // peerId -> { connection, isSuperPeer, relayCapacity }
        this._dhtSocket = null;
        this._dhtQueries = new Map(); // queryId -> { resolve, nodes, timer }
        this._dhtData = new Map(); // key -> value (DHT 本地存储)
        this._relayRoutes = new Map(); // targetPeerId -> relayPeerId
        this._meshConnections = new Set(); // peerIds in mesh
        this._starHub = null; // 星型中心节点
        this._dhtReady = false;
    }

    // ============================================================
    // Mesh 网状网络
    // ============================================================
    /**
     * 建立 Mesh：确保房间内所有已知节点两两互连
     */
    async buildMesh(peers, connectFn) {
        const peerIds = Array.isArray(peers) ? peers : [...peers];
        const connections = [];

        for (const peerId of peerIds) {
            if (this._meshConnections.has(peerId)) continue;
            if (peerId === this._nodeId.hex) continue;

            try {
                const conn = await connectFn(peerId);
                this._meshConnections.add(peerId);
                this._peers.set(peerId, { connection: conn, isSuperPeer: false, relayCapacity: 0 });
                connections.push({ peerId, connection: conn });
                this.emit('mesh:connected', { peerId });
            } catch (e) {
                this.emit('mesh:failed', { peerId, error: e.message });
            }
        }

        this.emit('mesh:built', { totalConnections: connections.length });
        return connections;
    }

    /**
     * 从 Mesh 中断开指定节点
     */
    disconnectFromMesh(peerId) {
        this._meshConnections.delete(peerId);
        this._peers.delete(peerId);
        this._removeRelayRoutes(peerId);
        this.emit('mesh:disconnected', { peerId });
    }

    getMeshPeers() {
        return [...this._meshConnections];
    }

    isMeshConnected(peerId) {
        return this._meshConnections.has(peerId);
    }

    // ============================================================
    // 星型拓扑（弱节点通过强节点转发）
    // ============================================================
    /**
     * 指定超级节点（星型中心）
     */
    setSuperPeer(peerId, options = {}) {
        const peer = this._peers.get(peerId);
        if (peer) {
            peer.isSuperPeer = true;
            peer.relayCapacity = options.relayCapacity || 10;
            this._starHub = peerId;
            this.emit('star:superPeer', { peerId, capacity: peer.relayCapacity });
        }
    }

    /**
     * 将弱节点连接到超级节点（星型辐条）
     */
    async connectToStar(weakPeerId, connectFn) {
        if (!this._starHub) {
            throw new Error('No super peer set');
        }

        const conn = await connectFn(this._starHub);
        this._peers.set(weakPeerId, {
            connection: conn,
            isSuperPeer: false,
            relayCapacity: 0,
            starHub: this._starHub
        });

        this.emit('star:connected', { weakPeerId, hub: this._starHub });
        return conn;
    }

    /**
     * 通过星型中心转发消息
     */
    async relayViaStar(targetPeerId, message, sendFn) {
        if (!this._starHub) {
            throw new Error('No super peer set');
        }
        const hubPeer = this._peers.get(this._starHub);
        if (!hubPeer) {
            throw new Error('Super peer not connected');
        }
        return await sendFn(this._starHub, {
            type: 'relay',
            target: targetPeerId,
            message
        });
    }

    getStarHub() {
        return this._starHub;
    }

    // ============================================================
    // 多跳中继
    // ============================================================
    /**
     * 设置中继路由
     * @param {string} targetPeerId - 目标节点
     * @param {string} relayPeerId - 中继节点
     */
    setRelayRoute(targetPeerId, relayPeerId) {
        this._relayRoutes.set(targetPeerId, relayPeerId);
        this.emit('relay:routeAdded', { target: targetPeerId, relay: relayPeerId });
    }

    /**
     * 查找到达目标的中继路径
     * @returns {string[]} 中继路径（不含起点和终点）
     */
    findRelayPath(targetPeerId, maxHops = 3) {
        // BFS 查找最短路径
        const visited = new Set([this._nodeId.hex]);
        const queue = [[this._nodeId.hex, []]];

        while (queue.length > 0) {
            const [current, path] = queue.shift();

            if (current === targetPeerId) {
                return path;
            }

            if (path.length >= maxHops) continue;

            // 获取当前节点的所有邻居
            const neighbors = this._getNeighbors(current);
            for (const neighbor of neighbors) {
                if (!visited.has(neighbor)) {
                    visited.add(neighbor);
                    queue.push([neighbor, [...path, neighbor]]);
                }
            }
        }

        return null; // 没有路径
    }

    /**
     * 通过中继发送消息
     */
    async relayMessage(targetPeerId, message, sendFn, maxHops = 3) {
        const directRoute = this._relayRoutes.get(targetPeerId);
        if (directRoute) {
            return await sendFn(directRoute, {
                type: 'relay-forward',
                target: targetPeerId,
                message,
                ttl: maxHops
            });
        }

        const path = this.findRelayPath(targetPeerId, maxHops);
        if (!path || path.length === 0) {
            throw new Error(`No route to ${targetPeerId}`);
        }

        const nextHop = path[0];
        return await sendFn(nextHop, {
            type: 'relay-forward',
            target: targetPeerId,
            message,
            path: path.slice(1),
            ttl: maxHops - 1
        });
    }

    /**
     * 处理收到的中继消息
     */
    handleRelayMessage(message, sendFn) {
        const { type, target, relayMessage, path, ttl } = message;

        if (type === 'relay-forward') {
            if (ttl <= 0) {
                this.emit('relay:ttlExceeded', { target, message: relayMessage });
                return;
            }

            if (target === this._nodeId.hex) {
                // 到达目标
                this.emit('relay:received', { message: relayMessage });
                return;
            }

            // 继续转发
            if (path && path.length > 0) {
                const nextHop = path.shift();
                sendFn(nextHop, { type: 'relay-forward', target, message: relayMessage, path, ttl: ttl - 1 });
            } else {
                // 通过路由表查找
                const route = this._relayRoutes.get(target);
                if (route) {
                    sendFn(route, { type: 'relay-forward', target, message: relayMessage, ttl: ttl - 1 });
                }
            }
        }
    }

    _getNeighbors(nodeId) {
        const neighbors = [];
        for (const [peerId, peer] of this._peers) {
            if (peer.connection) neighbors.push(peerId);
        }
        // 也添加 DHT 节点
        for (const node of this._routingTable.getAllNodes()) {
            neighbors.push(node.id.hex);
        }
        return [...new Set(neighbors)];
    }

    _removeRelayRoutes(peerId) {
        this._relayRoutes.delete(peerId);
        for (const [target, relay] of this._relayRoutes) {
            if (relay === peerId) this._relayRoutes.delete(target);
        }
    }

    // ============================================================
    // DHT 分布式哈希表
    // ============================================================
    /**
     * 启动 DHT 节点
     */
    async startDht(port) {
        if (this._dhtSocket) return;

        this._dhtSocket = dgram.createSocket('udp4');
        const dhtPort = port || this._options.dhtPort;

        this._dhtSocket.on('message', (msg, rinfo) => {
            this._handleDhtMessage(msg, rinfo);
        });

        this._dhtSocket.on('error', (err) => {
            this.emit('dht:error', { error: err.message });
        });

        this._dhtSocket.bind(dhtPort, () => {
            this._dhtReady = true;
            this.emit('dht:ready', { port: dhtPort, nodeId: this._nodeId.short });

            // Bootstrap
            this._bootstrap();
        });

        // 定期刷新
        this._refreshTimer = setInterval(() => this._refreshBuckets(), REFRESH_INTERVAL);
        this._pingTimer = setInterval(() => this._pingPeers(), PING_INTERVAL);
    }

    /**
     * 停止 DHT
     */
    stopDht() {
        if (this._refreshTimer) clearInterval(this._refreshTimer);
        if (this._pingTimer) clearInterval(this._pingTimer);
        if (this._dhtSocket) {
            this._dhtSocket.close();
            this._dhtSocket = null;
        }
        this._dhtReady = false;
        this.emit('dht:stopped');
    }

    /**
     * 在 DHT 中存储值
     */
    async dhtStore(key, value) {
        const keyId = NodeId.fromHex(key);
        const closest = this._routingTable.findClosest(keyId, K_BUCKET_SIZE);
        const results = [];

        for (const node of closest) {
            try {
                await this._dhtQuery(node, 'store', { key, value });
                results.push(node.id.short);
            } catch (e) {
                // 节点不可达，移除
                this._routingTable.removeNode(node.id);
            }
        }

        return results;
    }

    /**
     * 从 DHT 中查找值
     */
    async dhtFind(key) {
        const keyId = NodeId.fromHex(key);
        return await this._dhtFindValue(keyId);
    }

    /**
     * 查找节点
     */
    async dhtFindNode(targetId) {
        return await this._dhtNodeLookup(targetId);
    }

    async _dhtFindValue(targetId) {
        const closest = this._routingTable.findClosest(targetId, ALPHA);
        const queried = new Set();
        const results = [];

        const query = async (node) => {
            if (queried.has(node.id.hex)) return;
            queried.add(node.id.hex);

            try {
                const response = await this._dhtQuery(node, 'find_value', { target: targetId.hex });
                if (response.value) {
                    results.push(response.value);
                }
                if (response.nodes) {
                    for (const n of response.nodes) {
                        if (!queried.has(n.id.hex)) {
                            this._routingTable.addNode(n);
                            await query(n);
                        }
                    }
                }
            } catch (e) {
                this._routingTable.removeNode(node.id);
            }
        };

        await Promise.all(closest.map(n => query(n)));
        return results;
    }

    async _dhtNodeLookup(targetId) {
        const closest = this._routingTable.findClosest(targetId, ALPHA);
        const queried = new Set([this._nodeId.hex]);
        const shortlist = [...closest];

        while (shortlist.some(n => !queried.has(n.id.hex))) {
            const unqueried = shortlist.filter(n => !queried.has(n.id.hex)).slice(0, ALPHA);
            const responses = await Promise.all(
                unqueried.map(n => {
                    queried.add(n.id.hex);
                    return this._dhtQuery(n, 'find_node', { target: targetId.hex }).catch(() => null);
                })
            );

            for (const resp of responses) {
                if (resp && resp.nodes) {
                    for (const node of resp.nodes) {
                        if (!queried.has(node.id.hex)) {
                            this._routingTable.addNode(node);
                            shortlist.push(node);
                        }
                    }
                }
            }

            shortlist.sort((a, b) => {
                const da = targetId.distance(a.id);
                const db = targetId.distance(b.id);
                return Buffer.compare(da, db);
            });
        }

        return shortlist.filter(n => queried.has(n.id.hex));
    }

    _handleDhtMessage(msg, rinfo) {
        try {
            const message = this._decodeDhtMessage(msg);
            if (!message) return;

            const { type, queryId, nodeId, data } = message;
            const senderId = NodeId.fromHex(nodeId);

            // 添加发送者到路由表
            this._routingTable.addNode({
                id: senderId,
                address: rinfo.address,
                port: rinfo.port
            });

            switch (type) {
                case 'ping': {
                    this._sendDhtResponse(rinfo, queryId, { type: 'pong', nodeId: this._nodeId.hex });
                    break;
                }
                case 'find_node': {
                    const target = NodeId.fromHex(data.target);
                    const closest = this._routingTable.findClosest(target, K_BUCKET_SIZE);
                    this._sendDhtResponse(rinfo, queryId, {
                        type: 'find_node_reply',
                        nodes: closest.map(n => ({
                            id: n.id.hex,
                            address: n.address,
                            port: n.port
                        }))
                    });
                    break;
                }
                case 'find_value': {
                    // 查找本地存储
                    const stored = this._dhtData.has(data.target) ? this._dhtData.get(data.target) : null;
                    if (stored) {
                        this._sendDhtResponse(rinfo, queryId, {
                            type: 'find_value_reply',
                            value: stored
                        });
                    } else {
                        const target = NodeId.fromHex(data.target);
                        const closest = this._routingTable.findClosest(target, K_BUCKET_SIZE);
                        this._sendDhtResponse(rinfo, queryId, {
                            type: 'find_value_reply',
                            nodes: closest.map(n => ({
                                id: n.id.hex,
                                address: n.address,
                                port: n.port
                            }))
                        });
                    }
                    break;
                }
                case 'store': {
                    this._dhtData.set(data.key, data.value);
                    this._sendDhtResponse(rinfo, queryId, { type: 'store_ack' });
                    break;
                }
                // 响应消息
                case 'pong':
                case 'find_node_reply':
                case 'find_value_reply':
                case 'store_ack': {
                    const query = this._dhtQueries.get(queryId);
                    if (query) {
                        clearTimeout(query.timer);
                        query.resolve(message);
                        this._dhtQueries.delete(queryId);
                    }
                    break;
                }
            }
        } catch (e) {
            // 忽略无效消息
        }
    }

    _dhtQuery(node, type, data = {}) {
        return new Promise((resolve, reject) => {
            const queryId = crypto.randomBytes(4).toString('hex');
            const message = this._encodeDhtMessage({
                type,
                queryId,
                nodeId: this._nodeId.hex,
                data
            });

            const timer = setTimeout(() => {
                this._dhtQueries.delete(queryId);
                reject(new Error(`DHT query timeout: ${type}`));
            }, 5000);

            this._dhtQueries.set(queryId, { resolve, timer });

            this._dhtSocket.send(message, 0, message.length, node.port, node.address);
        });
    }

    _sendDhtResponse(rinfo, queryId, data) {
        const message = this._encodeDhtMessage({
            ...data,
            queryId,
            nodeId: this._nodeId.hex
        });
        this._dhtSocket.send(message, 0, message.length, rinfo.port, rinfo.address);
    }

    _encodeDhtMessage(message) {
        return Buffer.from(JSON.stringify(message), 'utf8');
    }

    _decodeDhtMessage(buffer) {
        try {
            return JSON.parse(buffer.toString('utf8'));
        } catch (e) {
            return null;
        }
    }

    _bootstrap() {
        const bootstrapNodes = this._options.bootstrapNodes;
        for (const node of bootstrapNodes) {
            try {
                const [host, port] = node.split(':');
                this._dhtQuery(
                    { address: host, port: parseInt(port) || DHT_PORT },
                    'ping'
                ).catch(() => {});
            } catch (e) { /* ignore */ }
        }
    }

    async _refreshBuckets() {
        for (let i = 0; i < 160; i++) {
            const bucket = this._routingTable._buckets[i];
            if (bucket.length === 0) continue;

            // 生成随机的 target ID 在这个桶范围内
            const randomId = NodeId.random();
            await this._dhtNodeLookup(randomId).catch(() => {});
        }
    }

    async _pingPeers() {
        const nodes = this._routingTable.getAllNodes();
        for (const node of nodes) {
            try {
                await this._dhtQuery(node, 'ping');
            } catch (e) {
                this._routingTable.removeNode(node.id);
            }
        }
    }

    // ============================================================
    // 状态
    // ============================================================
    get nodeId() { return this._nodeId; }
    get dhtReady() { return this._dhtReady; }
    get routingTableSize() { return this._routingTable.size; }

    getStatus() {
        return {
            nodeId: this._nodeId.short,
            dht: {
                ready: this._dhtReady,
                routingTableSize: this._routingTable.size,
                stats: this._routingTable.getStats()
            },
            mesh: {
                connections: this._meshConnections.size,
                peers: this.getMeshPeers()
            },
            star: {
                hub: this._starHub,
                relayCapacity: this._starHub ? this._peers.get(this._starHub)?.relayCapacity || 0 : 0
            },
            relay: {
                routes: this._relayRoutes.size,
                routesList: Object.fromEntries(this._relayRoutes)
            }
        };
    }
}

module.exports = { NetworkTopology, NodeId, RoutingTable };