const crypto = require('crypto');
const dgram = require('dgram');
const RTCSessionDescription = require('./session-description');
const RTCIceCandidate = require('./ice-candidate');
const RTCDataChannel = require('./data-channel');
const IceManager = require('./ice-manager');
const { DtlsHandshake } = require('./dtls-handshake');

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
        const sdp = this._remoteDescription ? this._remoteDescription.sdp : '';
        const ufragMatch = sdp.match(/a=ice-ufrag:(\S+)/);
        const pwdMatch = sdp.match(/a=ice-pwd:(\S+)/);
        await this._iceManager.startConnecting(ufragMatch ? ufragMatch[1] : null, pwdMatch ? pwdMatch[1] : null);
    }

    async addIceCandidate(candidate) {
        if (!(candidate instanceof RTCIceCandidate)) {
            candidate = new RTCIceCandidate(candidate);
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
        
        this._dtls = new DtlsHandshake();
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
        
        this._remoteFingerprint = remoteFingerprint;
        
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
        this._remoteFingerprint = remoteDtls.localFingerprint;
        
        return this.performDtlsHandshake(remoteDtls.localFingerprint);
    }

    _parseRemoteFingerprint(sdp) {
        const match = sdp.match(/a=fingerprint:sha-256\s+([0-9A-F:]+)/i);
        if (match) {
            this._remoteFingerprint = match[1].toUpperCase();
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
        const ufrag = this._iceManager.localUfrag;
        const pwd = this._iceManager.localPwd;
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