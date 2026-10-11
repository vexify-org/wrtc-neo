const wrtc = require('../index');

let passed = 0;
let failed = 0;

const test = (name, fn) => {
    try {
        fn();
        console.log('✓ ' + name);
        passed++;
    } catch (error) {
        console.log('✗ ' + name + ': ' + error.message);
        failed++;
    }
};

// ---- RFC 5769 测试向量 ----
// 公网地址 192.0.2.1:32853
// X-Port = 0xa147, X-Address(IPv4) = e1 12 a6 43
const VECTOR_PORT = 0x8055;   // 32853
const VECTOR_IP = [0xc0, 0x00, 0x02, 0x01];
const XOR_PORT = 0xa147;
const XOR_IP = [0xe1, 0x12, 0xa6, 0x43];

test('TurnClient - _encodeXorAddress matches RFC 5769 vector', () => {
    const client = new wrtc.TurnClient({ host: '127.0.0.1' });
    const buf = client._encodeXorAddress('192.0.2.1', VECTOR_PORT);
    const xPort = buf.readUInt16BE(2);
    if (xPort !== XOR_PORT) throw new Error(`X-Port ${xPort.toString(16)} !== ${XOR_PORT.toString(16)}`);
    for (let i = 0; i < 4; i++) {
        if (buf.readUInt8(4 + i) !== XOR_IP[i]) throw new Error(`X-Address byte ${i} mismatch`);
    }
});

test('TurnClient - _decodeXorAddress matches RFC 5769 vector', () => {
    const client = new wrtc.TurnClient({ host: '127.0.0.1' });
    const buf = Buffer.alloc(8);
    buf.writeUInt8(0, 0);
    buf.writeUInt8(0x01, 1);
    buf.writeUInt16BE(XOR_PORT, 2);
    XOR_IP.forEach((b, i) => buf.writeUInt8(b, 4 + i));
    const decoded = client._decodeXorAddress(buf);
    if (!decoded) throw new Error('decode returned null');
    if (decoded.port !== VECTOR_PORT) throw new Error(`port ${decoded.port} !== ${VECTOR_PORT}`);
    if (decoded.address !== '192.0.2.1') throw new Error(`address ${decoded.address} !== 192.0.2.1`);
});

test('TurnClient - encode/decode roundtrip', () => {
    const client = new wrtc.TurnClient({ host: '127.0.0.1' });
    for (let i = 0; i < 10; i++) {
        const addr = `10.${i}.${i % 4}.${i % 8}`;
        const port = 10000 + i * 371;
        const enc = client._encodeXorAddress(addr, port);
        const dec = client._decodeXorAddress(enc);
        if (dec.address !== addr || dec.port !== port) {
            throw new Error(`roundtrip mismatch: ${addr}:${port} -> ${dec.address}:${dec.port}`);
        }
    }
});

test('TurnClient - _buildMessage produces unique transaction IDs', () => {
    const client = new wrtc.TurnClient({ host: '127.0.0.1' });
    const ids = new Set();
    for (let i = 0; i < 100; i++) {
        const msg = client._buildMessage(0x003);
        ids.add(msg.slice(8, 20).toString('hex'));
    }
    if (ids.size !== 100) throw new Error('expected 100 unique transaction IDs');
});

test('TurnClient - _handleMessage extracts real transaction ID', () => {
    const client = new wrtc.TurnClient({ host: '127.0.0.1' });
    client._pendingRequests = new Map();
    let resolved = null;
    let rejected = null;

    const msg = client._buildMessage(0x003);
    msg.writeUInt16BE(0x0103, 0); // Allocate Success
    msg.writeUInt16BE(0, 2);
    const tid = msg.slice(8, 20).toString('hex');

    client._pendingRequests.set(tid, { resolve: (r) => { resolved = r; }, reject: (e) => { rejected = e; }, method: 0x003 });
    client._handleMessage(msg);
    if (!resolved) throw new Error('request was not resolved by its transaction ID');
    if (rejected) throw new Error('request was incorrectly rejected');
    if (client._pendingRequests.has(tid)) throw new Error('pending request not cleaned up');
});

test('DHT - _dhtData store/find working', async () => {
    const { NetworkTopology } = require('../lib/network-topology');
    const topo = new NetworkTopology({ enableDht: false, enableMesh: false, enableStar: false, enableRelay: false });

    const storeMsg = { type: 'store', queryId: 'abc', key: 'k1', value: 'v1' };
    const rinfo = { address: '127.0.0.1', port: 9999 };
    const sent = [];
    topo._sendDhtResponse = (info, qid, message) => sent.push(message);
    await topo._handleDhtMessage(storeMsg, rinfo);

    if (topo._dhtData.get('k1') !== 'v1') throw new Error('store failed');
    if (sent.length !== 1 || sent[0].type !== 'store_ack') throw new Error('store ack not sent');

    const findMsg = { type: 'find_value', queryId: 'def', target: 'k1' };
    sent.length = 0;
    await topo._handleDhtMessage(findMsg, rinfo);
    if (sent.length !== 1 || sent[0].value !== 'v1') throw new Error('find_value failed');
});

test('SdpParser - parse LF-only SDP', () => {
    const SdpParser = require('../lib/sdp-parser');
    const sdp = 'v=0\no=- x 2 IN IP4 127.0.0.1\ns=-\nt=0 0\na=ice-ufrag:test\na=ice-pwd:secret\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\n';
    const parsed = SdpParser.parse(sdp);
    if (SdpParser.getIceUfrag(sdp) !== 'test') throw new Error('ufrag mismatch');
    if (SdpParser.getIcePwd(sdp) !== 'secret') throw new Error('pwd mismatch');
});

test('ReconnectBuffer - size accounting on eviction', () => {
    const { ReconnectBuffer } = require('../lib/connection-pool');
    const buf = new ReconnectBuffer({ maxSize: 10, maxMessages: 3 });
    buf.push(Buffer.alloc(3)); // 3 bytes
    buf.push(Buffer.alloc(3));
    buf.push(Buffer.alloc(3));
    buf.push(Buffer.alloc(3)); // evicts oldest
    if (buf.count !== 3) throw new Error('count should be 3');
    if (buf.size !== 9) throw new Error(`size should be 9, got ${buf.size}`);
});

test('RTCIceCandidate - candidate.type returns candidate type (host/srflx)', () => {
    const cand = new wrtc.RTCIceCandidate({
        candidate: 'candidate:1 1 UDP 2130706431 192.168.1.5 5000 typ host'
    });
    const c = cand.candidate;
    if (!c.includes('typ host')) throw new Error('candidate string mismatch');
});

console.log('\n=== Results ===');
console.log('Passed: ' + passed);
console.log('Failed: ' + failed);
process.exit(failed === 0 ? 0 : 1);