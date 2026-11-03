const crypto = require('crypto');
const dgram = require('dgram');
const RTCSessionDescription = require('./session-description');
const RTCIceCandidate = require('./ice-candidate');
const RTCDataChannel = require('./data-channel');
const IceManager = require('./ice-manager');
const { DtlsHandshake, normalizeFingerprint } = require('./dtls-handshake');

/** ICE ufrag/pwd 允许的字符集（RFC 8445），并限制长度，防止 SDP 注入 */
function sanitizeIceCredential(value, maxLen) {
    if (typeof value !== 'string' || !value) return null;
    if (value.length > maxLen) return null;
    if (!/^[A-Za-z0-9+/=_-]+$/.test(value)) return null;
    return value;
}

class RTCPeerConnection {
    constructor(config = {}) {
        this._config = config;
        this._iceServers = config.iceServers || [];
        this._localDescription = null;
        this._remoteDescription = null;
        this._iceManager = new IceManager(this._iceServers, this);
        this._dataChannels = new Map();
        this._connectionState = 'new';
        
        // DTLS 握手
        this._dtls = null;
        this._remoteFingerprint = null;
        this._remoteFingerprintValid = false;
        this._setupRole = null; // 'active' | 'passive' | 'actpass'
        
        this._callbacks = {
            icecandidate: [],
            datachannel: [],
            connectionstatechange: [],
            iceconnectionstatechange: [],
            negotiationneeded: [],
            dtlsstatechange: []
        };
        
        this._iceManager.on('candidate', (candidate) => {
            this._emit('icecandidate', { candidate });
        });
        
        this._iceManager.on('connectionstatechange', (state) => {
            this._updateConnectionState(state);
        });
    }

    get connectionState() {
        return this._connectionState;
    }

    get iceConnectionState() {
        return this._iceManager ? this._iceManager.state : 'new';
    }

    get dtlsState() {
        return this._dtls ? this._dtls.state : 'idle';
    }

    get localDescription() {
        return this._localDescription;
    }

    get remoteDescription() {
        return this._remoteDescription;
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

    async createOffer(options = {}) {
        // 启动 DTLS 握手
        await this._startDtls();
        
        const offer = await this._createSdp('offer', options);
        return new RTCSessionDescription({
            type: 'offer',
            sdp: offer
        });
    }

    async createAnswer(options = {}) {
        // 启动 DTLS 握手
        await this._startDtls();
        
        const answer = await this._createSdp('answer', options);
        return new RTCSessionDescription({
            type: 'answer',
            sdp: answer
        });
    }

    async setLocalDescription(description) {
        if (!(description instanceof RTCSessionDescription)) {
            description = new RTCSessionDescription(description);
        }
        this._localDescription = description;

        // 注意: 本地 SDP 的 fingerprint 是本端自己的,绝不能当作远端指纹解析,
        // 否则 DTLS 会验证错误的指纹。远端指纹只能在 setRemoteDescription 时解析。

        // 无论 offer 还是 answer，本方都需要收集候选并建立检查列表
        if (description.type === 'offer' || description.type === 'answer') {
            await this._iceManager.startGathering();
            if (this._remoteDescription && (this._remoteDescription.type === 'offer' || this._remoteDescription.type === 'answer')) {
                await this.startConnectingFromRemote();
            }
        }
        
        return Promise.resolve();
    }

    async setRemoteDescription(description) {
        if (!(description instanceof RTCSessionDescription)) {
            description = new RTCSessionDescription(description);
        }
        this._remoteDescription = description;
        
        // 解析远端指纹
        this._parseRemoteFingerprint(description.sdp);
        
        // 记录远端 ICE 凭证，并开始连通性检查（offerer 收到 answer 后）
        if (description.type === 'answer') {
            await this.startConnectingFromRemote();
        }
        
        return Promise.resolve();
    }

    async startConnectingFromRemote() {
        if (!this._remoteDescription || typeof this._remoteDescription.sdp !== 'string') {
            return;
        }
        const sdp = this._remoteDescription.sdp;
        const ufragMatch = sdp.match(/a=ice-ufrag:([A-Za-z0-9+/=_-]+)/);
        const pwdMatch = sdp.match(/a=ice-pwd:([A-Za-z0-9+/=_-]+)/);
        const ufrag = sanitizeIceCredential(ufragMatch && ufragMatch[1], 256);
        const pwd = sanitizeIceCredential(pwdMatch && pwdMatch[1], 256);
        await this._iceManager.startConnecting(ufrag, pwd);
    }

    async addIceCandidate(candidate) {
        if (!(candidate instanceof RTCIceCandidate)) {
            candidate = new RTCIceCandidate(candidate);
        }

        if (candidate.candidate && !candidate.candidateType) {
            throw new Error('Invalid ICE candidate: missing candidate type');
        }
        if (candidate.port !== null && candidate.port !== undefined &&
            (!Number.isInteger(candidate.port) || candidate.port < 0 || candidate.port > 65535)) {
            throw new RangeError(`Invalid ICE candidate port: ${candidate.port}`);
        }
        
        if (candidate.candidate) {
            await this._iceManager.addRemoteCandidate(candidate);
        }
        
        return Promise.resolve();
    }

    createDataChannel(label, options = {}) {
        const channel = new RTCDataChannel(this, label, options);
        this._dataChannels.set(label, channel);
        this._emit('negotiationneeded');
        return channel;
    }

    close() {
        this._connectionState = 'closed';
        this._emit('connectionstatechange');
        
        if (this._dtls) {
            this._dtls.abort();
        }
        
        for (const channel of this._dataChannels.values()) {
            channel.close();
        }
        this._dataChannels.clear();
        
        if (this._iceManager) {
            this._iceManager.stop();
        }
    }

    // ============================================================
    // DTLS
    // ============================================================
    async _startDtls() {
        if (this._dtls) return;
        
        this._dtls = new DtlsHandshake({
            requireFingerprint: true,
            remoteFingerprint: this._remoteFingerprintValid ? this._remoteFingerprint : undefined
        });
        await this._dtls.start();
        
        this._dtls.on('stateChange', (state) => {
            this._emit('dtlsstatechange', state);
        });
        
        this._dtls.on('complete', (result) => {
            this._connectionState = 'connected';
            this._emit('connectionstatechange');
        });
    }

    async performDtlsHandshake(remoteFingerprint) {
        if (!this._dtls) return;
        // 指纹必须合法，否则握手会建立无认证通道（MITM 风险）
        const normalized = normalizeFingerprint(remoteFingerprint);
        if (!normalized) {
            throw new Error('Refusing DTLS handshake: missing or invalid remote SHA-256 fingerprint');
        }
        this._remoteFingerprint = normalized;
        this._remoteFingerprintValid = true;
        this._dtls.setExpectedFingerprint(normalized);
        
        // 生成 ClientHello
        const clientHello = this._dtls.generateClientHello();
        
        // 模拟完整的 DTLS 握手流程
        // 在实际场景中，这些消息会通过信令通道交换
        // 这里简化为：双方都知道对端的证书指纹，直接完成密钥交换
        
        // 生成服务端响应（模拟）
        const serverRandom = require('crypto').randomBytes(32);
        this._dtls.processServerHello({
            type: 'server_hello',
            version: 'DTLS 1.2',
            random: serverRandom.toString('hex'),
            cipherSuite: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
        });
        
        this._dtls.processServerCertificate({
            type: 'certificate',
            fingerprint: remoteFingerprint,
            curve: 'P-256'
        });
        
        // 生成服务端 ECDH 密钥对
        const serverEcdh = require('crypto').createECDH('prime256v1');
        serverEcdh.generateKeys();
        const serverPubKey = serverEcdh.getPublicKey(null, 'compressed');
        
        this._dtls.processServerKeyExchange({
            type: 'server_key_exchange',
            algorithm: 'ECDH',
            curve: 'P-256',
            publicKey: serverPubKey.toString('hex')
        });
        
        this._dtls.processServerHelloDone();
        
        // 客户端生成密钥交换
        const clientKeyExchange = this._dtls.generateClientKeyExchange();
        
        // 设置服务端 ECDH 公钥
        this._dtls.setServerEcdhPublicKey(serverPubKey.toString('hex'));
        
        // 生成并验证 Finished
        const clientFinished = this._dtls.generateClientFinished();
        
        // 使用和客户端相同的消息顺序计算 server Finished
        const allMsgs = [...this._dtls._handshakeMessages, ...this._dtls._remoteHandshakeMessages];
        const allHash = require('crypto').createHash('sha256').update(JSON.stringify(allMsgs)).digest();
        const { PRF } = require('./dtls-handshake');
        const serverFinished = {
            type: 'finished',
            verifyData: PRF(this._dtls._masterSecret, 'server finished', allHash, 12).toString('hex')
        };
        
        this._dtls.verifyServerFinished(serverFinished);
        this._dtls.completeHandshake();
        
        return true;
    }

    async exchangeDtlsMessages(remoteDtls) {
        if (!this._dtls || !remoteDtls) return false;

        // 简单握手：双方交换指纹后直接完成
        // 实际场景中，需要实现完整的请求/响应消息交换
        if (typeof remoteDtls.localFingerprint !== 'string' || !normalizeFingerprint(remoteDtls.localFingerprint)) {
            throw new Error('Remote DTLS instance has no valid local fingerprint');
        }
        this._remoteFingerprint = remoteDtls.localFingerprint;

        return this.performDtlsHandshake(remoteDtls.localFingerprint);
    }

    _parseRemoteFingerprint(sdp) {
        if (typeof sdp !== 'string') return;
        // 只接受 sha-256；其他算法一律忽略（避免降级到弱指纹）
        const match = sdp.match(/a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/);
        if (match) {
            const value = match[1].toUpperCase();
            // 兼容旧行为：保留原始值；是否可用于握手由 _remoteFingerprintValid 决定
            this._remoteFingerprint = value;
            this._remoteFingerprintValid = !!normalizeFingerprint(value);
        }
    }

    // 加密数据
    encryptData(data) {
        if (!this._dtls || this._dtls.state !== 'connected') {
            return { encrypted: false, data };
        }
        return this._dtls.encrypt(Buffer.isBuffer(data) ? data : Buffer.from(data));
    }

    // 解密数据
    decryptData(packet) {
        if (!this._dtls || this._dtls.state !== 'connected') {
            return { decrypted: false, data: packet };
        }
        return this._dtls.decrypt(packet);
    }

    // ============================================================
    // Internal
    // ============================================================
    async _createSdp(type, options) {
        // 与 IceManager 共享同一套 ICE 凭证，确保远端能够验证我们的 STUN 检查
        const ufrag = sanitizeIceCredential(this._iceManager.localUfrag, 256);
        const pwd = sanitizeIceCredential(this._iceManager.localPwd, 256);
        if (!ufrag || !pwd) {
            throw new Error('Invalid local ICE credentials');
        }
        const fp = this._dtls ? this._dtls.localFingerprint : '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00';
        const setup = type === 'offer' ? 'actpass' : 'active';
        this._setupRole = setup;

        // 会话级已包含 fingerprint/setup，媒体行不得重复输出(旧版重复两次,违反 RFC 5245/8843)
        const sdp = 'v=0\r\n' +
                    'o=- ' + Date.now() + ' 2 IN IP4 127.0.0.1\r\n' +
                    's=-\r\n' +
                    't=0 0\r\n' +
                    'a=group:BUNDLE 0\r\n' +
                    'a=msid-semantic: WMS\r\n' +
                    'a=ice-ufrag:' + ufrag + '\r\n' +
                    'a=ice-pwd:' + pwd + '\r\n' +
                    'a=ice-options:trickle\r\n' +
                    'a=fingerprint:sha-256 ' + fp + '\r\n' +
                    'a=setup:' + setup + '\r\n' +
                    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n' +
                    'c=IN IP4 0.0.0.0\r\n' +
                    'a=mid:0\r\n' +
                    'a=sctp-port:5000\r\n' +
                    'a=max-message-size:262144\r\n';
        
        return sdp;
    }

    _updateConnectionState(state) {
        this._connectionState = state;
        this._emit('connectionstatechange');
        this._emit('iceconnectionstatechange');
    }

    _emit(event, ...args) {
        if (this._callbacks[event]) {
            this._callbacks[event].forEach(cb => cb(...args));
        }
        if (this[`on${event}`]) {
            this[`on${event}`](...args);
        }
    }

    _getLocalCandidates() {
        return this._iceManager ? this._iceManager.localCandidates : [];
    }

    _onDataChannelOpened(channel) {
        this._emit('datachannel', { channel });
    }

    _establishConnection(address, port, protocol) {
        for (const channel of this._dataChannels.values()) {
            if (channel.readyState === 'connecting') {
                channel._openSocket(address, port, protocol);
            }
        }
    }
}

module.exports = RTCPeerConnection;