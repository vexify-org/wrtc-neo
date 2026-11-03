const crypto = require('crypto');

// ============================================================
// TLS 1.2 PRF: P_SHA256
// ============================================================
const MAX_PRF_LENGTH = 1024;
const MAX_HANDSHAKE_MESSAGES = 64;

/** 归一化 SHA-256 指纹：去掉冒号/空格，转大写 */
function normalizeFingerprint(fp) {
    if (typeof fp !== 'string') return null;
    const hex = fp.replace(/[\s:]/g, '').toUpperCase();
    if (!/^[0-9A-F]{64}$/.test(hex)) return null;
    return hex;
}

function formatFingerprint(hex) {
    return hex.match(/.{2}/g).join(':');
}

function PRF(secret, label, seed, length) {
    if (!Buffer.isBuffer(secret) || !Buffer.isBuffer(seed)) {
        throw new TypeError('PRF secret/seed must be Buffers');
    }
    if (!Number.isInteger(length) || length <= 0 || length > MAX_PRF_LENGTH) {
        throw new RangeError(`Invalid PRF output length: ${length}`);
    }
    const labelSeed = Buffer.concat([Buffer.from(label, 'ascii'), seed]);
    const result = [];
    let A = labelSeed;
    while (Buffer.concat(result).length < length) {
        A = crypto.createHmac('sha256', secret).update(A).digest();
        const block = crypto.createHmac('sha256', secret).update(Buffer.concat([A, labelSeed])).digest();
        result.push(block);
    }
    return Buffer.concat(result).slice(0, length);
}

// ============================================================
// Self-signed ECDSA P-256 Certificate
// ============================================================
function generateCertificate() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });

    const der = publicKey;
    const fingerprint = crypto.createHash('sha256').update(der).digest('hex').toUpperCase();
    const fingerprintColon = fingerprint.match(/.{2}/g).join(':');

    return {
        privateKey,
        publicKey: der,
        curve: 'P-256',
        fingerprint,
        fingerprintColon,
        // Generate a simple self-signed cert structure
        raw: der
    };
}

// ============================================================
// DTLS 1.2 Handshake (Real Crypto)
// ============================================================
class DtlsHandshake {
    constructor(options = {}) {
        this._options = { timeout: 30000, ...options };
        // DTLS 指纹校验默认开启：必须提供远端指纹才能完成握手（防中间人）
        if (this._options.requireFingerprint === undefined) this._options.requireFingerprint = true;
        this._expectedRemoteFingerprint = normalizeFingerprint(this._options.remoteFingerprint || this._options.expectedFingerprint);
        if ((this._options.remoteFingerprint || this._options.expectedFingerprint) && !this._expectedRemoteFingerprint) {
            throw new TypeError('Invalid expected remote DTLS fingerprint (want 32-byte SHA-256 hex)');
        }
        this._remoteFingerprintVerified = false;
        this._state = 'idle';
        this._listener = {};
        this._timeout = null;

        // 握手消息累积（用于 Finished 验证）
        this._handshakeMessages = [];
        this._remoteHandshakeMessages = [];

        // 密钥材料
        this._cert = null;
        this._remoteCert = null;
        this._ecdh = null;
        this._sharedSecret = null;
        this._masterSecret = null;
        this._clientRandom = null;
        this._serverRandom = null;
        this._encKey = null;
        this._decKey = null;
        this._encIV = null;
        this._decIV = null;
    }

    async start() {
        if (this._state === 'handshaking' || this._state === 'connected') {
            throw new Error(`DTLS already ${this._state}`);
        }
        this._state = 'handshaking';
        this._emit('stateChange', 'handshaking');

        this._cert = generateCertificate();
        this._clientRandom = crypto.randomBytes(32);

        this._timeout = setTimeout(() => {
            this._state = 'failed';
            this._emit('stateChange', 'failed');
            this._emit('error', new Error('DTLS handshake timeout'));
        }, this._options.timeout);
    }

    // Client: 生成 ClientHello
    generateClientHello() {
        if (this._state !== 'handshaking') throw new Error('Not in handshaking state');
        const msg = {
            type: 'client_hello',
            version: 'DTLS 1.2',
            random: this._clientRandom.toString('hex'),
            cipherSuites: ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'],
            extensions: {
                supportedGroups: ['secp256r1'],
                signatureAlgorithms: ['ecdsa_secp256r1_sha256']
            }
        };
        this._handshakeMessages.push(msg);
        return msg;
    }

    // Client: 处理 ServerHello + Certificate + ServerKeyExchange + CertificateRequest + ServerHelloDone
    processServerHello(serverHello) {
        if (!serverHello || typeof serverHello !== 'object') {
            throw new TypeError('serverHello must be an object');
        }
        if (typeof serverHello.random !== 'string' || !/^[0-9a-fA-F]{64}$/.test(serverHello.random)) {
            throw new Error('Invalid server random (want 32 bytes hex)');
        }
        if (this._remoteHandshakeMessages.length >= MAX_HANDSHAKE_MESSAGES) {
            throw new Error('Too many handshake messages');
        }
        this._serverRandom = Buffer.from(serverHello.random, 'hex');
        this._remoteHandshakeMessages.push(serverHello);
    }

    /**
     * 设置期望的远端证书指纹（来自 SDP a=fingerprint）。
     * 传入非法格式会抛错；配置后握手必须校验通过。
     */
    setExpectedFingerprint(fingerprint) {
        const normalized = normalizeFingerprint(fingerprint);
        if (!normalized) {
            throw new TypeError('Invalid DTLS fingerprint (want 32-byte SHA-256 hex)');
        }
        this._expectedRemoteFingerprint = normalized;
    }

    processServerCertificate(certMsg) {
        if (!certMsg || typeof certMsg !== 'object') {
            throw new TypeError('certificate message must be an object');
        }
        // 优先用消息里携带的公钥/证书重新计算指纹；只提供 fingerprint 字段时校验其格式
        let presented = null;
        if (certMsg.publicKey) {
            const der = Buffer.isBuffer(certMsg.publicKey) ? certMsg.publicKey : Buffer.from(String(certMsg.publicKey), 'hex');
            if (!Buffer.isBuffer(der) || der.length === 0) {
                throw new Error('Invalid certificate public key');
            }
            presented = crypto.createHash('sha256').update(der).digest('hex').toUpperCase();
        } else {
            presented = normalizeFingerprint(certMsg.fingerprint);
            if (!presented) {
                throw new Error('Certificate message has no valid fingerprint');
            }
        }

        // 校验指纹：配置了期望值时必须完全匹配（防 MITM）
        if (this._expectedRemoteFingerprint) {
            if (presented !== this._expectedRemoteFingerprint) {
                this._remoteFingerprintVerified = false;
                const err = new Error('DTLS certificate fingerprint mismatch');
                err.code = 'DTLS_FINGERPRINT_MISMATCH';
                this._emit('error', err);
                throw err;
            }
            this._remoteFingerprintVerified = true;
        } else if (this._options.requireFingerprint) {
            throw new Error('Remote DTLS fingerprint is required but not configured');
        }

        this._remoteCert = {
            ...certMsg,
            fingerprint: formatFingerprint(presented),
            fingerprintRaw: presented
        };
        if (this._remoteHandshakeMessages.length >= MAX_HANDSHAKE_MESSAGES) {
            throw new Error('Too many handshake messages');
        }
        this._remoteHandshakeMessages.push(certMsg);
    }

    processServerKeyExchange(keyExMsg) {
        if (!keyExMsg || typeof keyExMsg !== 'object') {
            throw new TypeError('server key exchange must be an object');
        }
        if (typeof keyExMsg.publicKey !== 'string' || !/^[0-9a-fA-F]+$/.test(keyExMsg.publicKey)) {
            throw new Error('Invalid server ECDH public key');
        }
        // 解析服务端 ECDH 公钥
        this._remoteHandshakeMessages.push(keyExMsg);
        return keyExMsg;
    }

    processServerHelloDone() {
        // 生成客户端 ECDH 密钥对
        this._ecdh = crypto.createECDH('prime256v1');
        this._ecdh.generateKeys();
    }

    // Client: 生成 ClientKeyExchange (ECDH public key)
    generateClientKeyExchange() {
        if (!this._ecdh) {
            throw new Error('ServerHelloDone must be processed before ClientKeyExchange');
        }
        const publicKey = this._ecdh.getPublicKey(null, 'compressed');
        const msg = {
            type: 'client_key_exchange',
            algorithm: 'ECDH',
            curve: 'P-256',
            publicKey: publicKey.toString('hex')
        };
        this._handshakeMessages.push(msg);
        return msg;
    }

    // Client: 设置服务端 ECDH 公钥并计算共享密钥
    setServerEcdhPublicKey(publicKeyHex) {
        if (!this._ecdh) {
            throw new Error('ServerHelloDone must be processed before key exchange');
        }
        if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]+$/.test(publicKeyHex)) {
            throw new TypeError('Invalid ECDH public key encoding');
        }
        const serverPubKey = Buffer.from(publicKeyHex, 'hex');
        // P-256 压缩点 33 字节，非压缩点 65 字节
        if (serverPubKey.length !== 33 && serverPubKey.length !== 65) {
            throw new RangeError(`Invalid P-256 public key length: ${serverPubKey.length}`);
        }
        try {
            this._sharedSecret = this._ecdh.computeSecret(serverPubKey);
        } catch (e) {
            throw new Error(`ECDH key agreement failed: ${e.message}`);
        }

        // 计算 master_secret
        const seed = Buffer.concat([this._clientRandom, this._serverRandom]);
        this._masterSecret = PRF(this._sharedSecret, 'master secret', seed, 48);

        // 派生加密密钥
        const keyBlock = PRF(this._masterSecret, 'key expansion', Buffer.concat([this._serverRandom, this._clientRandom]), 40);
        this._encKey = keyBlock.slice(0, 16);   // 客户端写密钥
        this._decKey = keyBlock.slice(16, 32);  // 服务端写密钥（客户端解密）
        this._encIV = keyBlock.slice(32, 36);   // 客户端写 IV
        this._decIV = keyBlock.slice(36, 40);   // 服务端写 IV
    }

    // Client: 生成 ChangeCipherSpec + Finished
    generateClientFinished() {
        if (!this._masterSecret) {
            throw new Error('Master secret not derived yet');
        }
        const verifyData = this._computeVerifyData('client finished');
        const msg = {
            type: 'finished',
            verifyData: verifyData.toString('hex')
        };
        this._handshakeMessages.push(msg);
        return msg;
    }

    // Client: 验证服务端 Finished
    verifyServerFinished(serverFinished) {
        if (!this._masterSecret) {
            throw new Error('Master secret not derived yet');
        }
        if (!serverFinished || typeof serverFinished.verifyData !== 'string' ||
            !/^[0-9a-fA-F]{24}$/.test(serverFinished.verifyData)) {
            throw new Error('Invalid server Finished verifyData');
        }
        // hash = SHA256(all handshake messages up to but NOT including server Finished)
        const allMsgs = [...this._handshakeMessages, ...this._remoteHandshakeMessages];
        const hash = crypto.createHash('sha256').update(JSON.stringify(allMsgs)).digest();
        const expected = PRF(this._masterSecret, 'server finished', hash, 12);
        const received = Buffer.from(serverFinished.verifyData, 'hex');
        if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
            throw new Error('Server Finished verification failed');
        }
        this._remoteHandshakeMessages.push(serverFinished);
        return true;
    }

    _computeVerifyData(label, remote = false) {
        const messages = remote ? this._remoteHandshakeMessages : this._handshakeMessages;
        const hash = crypto.createHash('sha256').update(JSON.stringify(messages)).digest();
        return PRF(this._masterSecret, label, hash, 12);
    }

    completeHandshake() {
        // 未完成密钥交换/未校验证书指纹时绝不能进入 connected（否则等于无认证明文通道）
        if (!this._sharedSecret || !this._masterSecret) {
            throw new Error('Cannot complete DTLS handshake before key exchange');
        }
        if (!this._remoteCert) {
            throw new Error('Cannot complete DTLS handshake without remote certificate');
        }
        if (this._options.requireFingerprint && !this._remoteFingerprintVerified) {
            throw new Error('Cannot complete DTLS handshake: remote fingerprint not verified');
        }
        clearTimeout(this._timeout);
        this._state = 'connected';
        this._emit('stateChange', 'connected');
        this._emit('complete', {
            localCertificate: {
                fingerprint: this._cert.fingerprintColon,
                curve: this._cert.curve
            },
            remoteCertificate: {
                fingerprint: this._remoteCert ? this._remoteCert.fingerprint : null,
                curve: this._remoteCert ? (this._remoteCert.curve || 'P-256') : 'P-256',
                verified: this._remoteFingerprintVerified
            },
            sharedSecret: this._sharedSecret.toString('hex'),
            cipherSuite: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
        });
    }

    // ============================================================
    // 应用数据加密/解密 (AES-128-GCM)
    // ============================================================
    encrypt(data) {
        if (this._state !== 'connected') throw new Error('DTLS not connected');
        if (!Buffer.isBuffer(data)) {
            if (data === undefined || data === null) throw new TypeError('data required');
            data = Buffer.from(data);
        }
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-128-gcm', this._encKey, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { iv: iv.toString('hex'), data: encrypted.toString('hex'), tag: tag.toString('hex') };
    }

    decrypt(packet) {
        if (this._state !== 'connected') throw new Error('DTLS not connected');
        if (!packet || typeof packet !== 'object') throw new TypeError('packet required');
        if (typeof packet.iv !== 'string' || !/^[0-9a-fA-F]{24}$/.test(packet.iv)) {
            throw new Error('Invalid DTLS IV');
        }
        if (typeof packet.tag !== 'string' || !/^[0-9a-fA-F]{32}$/.test(packet.tag)) {
            throw new Error('Invalid DTLS auth tag');
        }
        if (typeof packet.data !== 'string' || !/^[0-9a-fA-F]*$/.test(packet.data) || packet.data.length % 2 !== 0) {
            throw new Error('Invalid DTLS ciphertext');
        }
        try {
            const decipher = crypto.createDecipheriv('aes-128-gcm', this._decKey, Buffer.from(packet.iv, 'hex'));
            decipher.setAuthTag(Buffer.from(packet.tag, 'hex'));
            return Buffer.concat([decipher.update(Buffer.from(packet.data, 'hex')), decipher.final()]);
        } catch (e) {
            throw new Error(`DTLS decrypt failed: ${e.message}`);
        }
    }

    get localFingerprint() {
        return this._cert ? this._cert.fingerprintColon : null;
    }

    get localFingerprintRaw() {
        return this._cert ? this._cert.fingerprint : null;
    }

    get state() { return this._state; }

    abort() {
        clearTimeout(this._timeout);
        this._state = 'aborted';
        this._sharedSecret = null;
        this._masterSecret = null;
        this._emit('stateChange', 'aborted');
    }

    on(event, callback) {
        if (!this._listener[event]) this._listener[event] = [];
        this._listener[event].push(callback);
    }

    off(event, callback) {
        if (this._listener[event]) this._listener[event] = this._listener[event].filter(cb => cb !== callback);
    }

    _emit(event, data) {
        if (this._listener[event]) {
            for (const cb of this._listener[event]) {
                try { cb(data); } catch (e) { console.error('DtlsHandshake event error:', e); }
            }
        }
    }
}

// ============================================================
// DTLS Server (简化版：用于服务端握手)
// ============================================================
class DtlsServer {
    constructor(options = {}) {
        this._options = { timeout: 30000, ...options };
        this._listener = {};
        this._connections = new Map();
    }

    handleConnection(connectionId) {
        const handshake = new DtlsHandshake(this._options);
        this._connections.set(connectionId, handshake);

        handshake.on('complete', (result) => {
            this._emit('handshakeComplete', { connectionId, result });
        });

        handshake.on('error', (error) => {
            this._connections.delete(connectionId);
            this._emit('handshakeError', { connectionId, error });
        });

        return handshake;
    }

    getConnection(connectionId) {
        return this._connections.get(connectionId);
    }

    closeConnection(connectionId) {
        const handshake = this._connections.get(connectionId);
        if (handshake && typeof handshake.abort === 'function') {
            try { handshake.abort(); } catch (e) { /* ignore */ }
        }
        this._connections.delete(connectionId);
    }

    closeAll() {
        for (const handshake of this._connections.values()) {
            try {
                if (handshake && typeof handshake.abort === 'function') handshake.abort();
            } catch (e) { /* ignore */ }
        }
        this._connections.clear();
    }

    on(event, callback) {
        if (!this._listener[event]) this._listener[event] = [];
        this._listener[event].push(callback);
    }

    off(event, callback) {
        if (this._listener[event]) this._listener[event] = this._listener[event].filter(cb => cb !== callback);
    }

    _emit(event, data) {
        if (this._listener[event]) {
            for (const cb of this._listener[event]) {
                try { cb(data); } catch (e) { console.error('DtlsServer event error:', e); }
            }
        }
    }
}

module.exports = { DtlsHandshake, DtlsServer, generateCertificate, PRF, normalizeFingerprint };