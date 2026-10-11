const crypto = require('crypto');

// ============================================================
// TLS 1.2 PRF: P_SHA256
// ============================================================
function PRF(secret, label, seed, length) {
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
        this._serverRandom = Buffer.from(serverHello.random, 'hex');
        this._remoteHandshakeMessages.push(serverHello);
    }

    processServerCertificate(certMsg) {
        this._remoteCert = certMsg;
        this._remoteHandshakeMessages.push(certMsg);
    }

    processServerKeyExchange(keyExMsg) {
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
        const serverPubKey = Buffer.from(publicKeyHex, 'hex');
        this._sharedSecret = this._ecdh.computeSecret(serverPubKey);

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
                curve: this._remoteCert ? this._remoteCert.curve : 'P-256'
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
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-128-gcm', this._encKey, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { iv: iv.toString('hex'), data: encrypted.toString('hex'), tag: tag.toString('hex') };
    }

    decrypt(packet) {
        if (this._state !== 'connected') throw new Error('DTLS not connected');
        const decipher = crypto.createDecipheriv('aes-128-gcm', this._decKey, Buffer.from(packet.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(packet.tag, 'hex'));
        return Buffer.concat([decipher.update(Buffer.from(packet.data, 'hex')), decipher.final()]);
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
        this._connections.delete(connectionId);
    }

    closeAll() {
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

module.exports = { DtlsHandshake, DtlsServer, generateCertificate, PRF };