// HolePuncher 打洞流程测试（本地 UDP mock STUN）
const dgram = require('dgram');
const wrtc = require('../index');

let passed = 0, failed = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const MAGIC = 0x2112a442;

function buildBindingResponse(tid, address, port, useXor = true) {
    const attrLen = 12;
    const resp = Buffer.alloc(20 + attrLen);
    resp.writeUInt16BE(0x0101, 0);
    resp.writeUInt16BE(attrLen, 2);
    resp.writeUInt32BE(MAGIC, 4);
    tid.copy(resp, 8);
    const ip = address.split('.').map(Number);
    if (useXor) {
        resp.writeUInt16BE(0x0020, 20); // XOR-MAPPED-ADDRESS
        resp.writeUInt16BE(8, 22);
        resp.writeUInt8(0, 24);
        resp.writeUInt8(1, 25); // IPv4
        resp.writeUInt16BE(port ^ 0x2112, 26);
        resp.writeUInt8(ip[0] ^ 0x21, 28);
        resp.writeUInt8(ip[1] ^ 0x12, 29);
        resp.writeUInt8(ip[2] ^ 0xa4, 30);
        resp.writeUInt8(ip[3] ^ 0x42, 31);
    } else {
        resp.writeUInt16BE(0x0001, 20); // MAPPED-ADDRESS
        resp.writeUInt16BE(8, 22);
        resp.writeUInt8(0, 24);
        resp.writeUInt8(1, 25);
        resp.writeUInt16BE(port, 26);
        resp.writeUInt8(ip[0], 28);
        resp.writeUInt8(ip[1], 29);
        resp.writeUInt8(ip[2], 30);
        resp.writeUInt8(ip[3], 31);
    }
    return resp;
}

function startMockStun(port, { mapped = ['203.0.113.9', 40000], mode = 'ok' } = {}) {
    return new Promise((resolve) => {
        const sock = dgram.createSocket('udp4');
        const log = [];
        sock.on('message', (msg, rinfo) => {
            log.push({ size: msg.length, srcPort: rinfo.port });
            if (mode === 'silent') return;
            if (mode === 'garbage') { sock.send(Buffer.from([0xff, 0xfe, 0x01]), rinfo.port, rinfo.address); return; }
            const tid = msg.slice(8, 20);
            const badTid = mode === 'wrong-tid' ? Buffer.alloc(12, 0x33) : tid;
            sock.send(buildBindingResponse(badTid, mapped[0], mapped[1]), rinfo.port, rinfo.address);
        });
        sock.bind(port, '127.0.0.1', () => resolve({
            sock, log,
            port: sock.address().port,
            close: () => { try { sock.close(); } catch (e) {} }
        }));
    });
}

test('start() resolves with bound port', async () => {
    const hp = new wrtc.HolePuncher();
    const port = await hp.start(0);
    if (!hp.localPort || hp.state !== 'ready') throw new Error(`state=${hp.state}`);
    if (port !== hp.localPort) throw new Error('resolve value != localPort');
    hp.stop();
});

test('start() rejects on port conflict instead of hanging forever', async () => {
    const blocker = await startMockStun(0);
    const hp = new wrtc.HolePuncher();
    const raced = await Promise.race([
        hp.start(blocker.port).then(() => 'resolved').catch(() => 'rejected'),
        sleep(1500).then(() => 'hang')
    ]);
    blocker.close();
    if (raced !== 'rejected') throw new Error(`start() ${raced} on EADDRINUSE (bug: promise never settles)`);
});

test('discoverPublicAddress() parses XOR-MAPPED-ADDRESS', async () => {
    const stun = await startMockStun(0);
    const hp = new wrtc.HolePuncher();
    await hp.start(0);
    const info = await hp.discoverPublicAddress('127.0.0.1', stun.port);
    if (info.address !== '203.0.113.9' || info.port !== 40000) throw new Error(`${info.address}:${info.port}`);
    if (hp.getPublicAddress().address !== '203.0.113.9') throw new Error('publicAddress not stored');
    hp.stop(); stun.close();
});

test('discoverPublicAddress() rejects on timeout and removes listener', async () => {
    const stun = await startMockStun(0, { mode: 'silent' });
    const hp = new wrtc.HolePuncher();
    await hp.start(0);
    const before = hp.socket.listenerCount('message');
    let err = null;
    try {
        // 内部超时固定 5s — 用 race 缩短测试等待意义不大，改为验证 silent 时确实 reject：
        // 直接等内部 timeout 太长，这里断言在 5.5s 内 reject。
        await Promise.race([
            hp.discoverPublicAddress('127.0.0.1', stun.port).then(() => (err = null)).catch(e => { err = e; }),
            sleep(5600).then(() => { err = err || new Error('never settled'); })
        ]);
    } catch (e) { err = e; }
    const after = hp.socket.listenerCount('message');
    hp.stop(); stun.close();
    if (!err || !/timeout/i.test(err.message)) throw new Error(`did not reject with timeout: ${err && err.message}`);
    if (after !== before) throw new Error(`message listener leaked: ${before} -> ${after}`);
});

test('discoverPublicAddress() ignores wrong transaction id then times out', async () => {
    const stun = await startMockStun(0, { mode: 'wrong-tid' });
    const hp = new wrtc.HolePuncher();
    await hp.start(0);
    const err = await Promise.race([
        hp.discoverPublicAddress('127.0.0.1', stun.port).then(() => null).catch(e => e),
        sleep(5600).then(() => new Error('never settled'))
    ]);
    hp.stop(); stun.close();
    if (!err) throw new Error('wrong-tid response was accepted');
});

test('malformed STUN response does not crash process', async () => {
    let uncaught = null;
    const onUncaught = (e) => { uncaught = e; };
    process.on('uncaughtException', onUncaught);
    const stun = await startMockStun(0, { mode: 'garbage' });
    const hp = new wrtc.HolePuncher();
    await hp.start(0);
    await Promise.race([
        hp.discoverPublicAddress('127.0.0.1', stun.port).catch(() => {}),
        sleep(5600)
    ]);
    hp.stop(); stun.close();
    process.removeListener('uncaughtException', onUncaught);
    if (uncaught) throw new Error(`uncaught exception: ${uncaught.message}`);
});

test('punch handshake: both sides learn each other', async () => {
    const a = new wrtc.HolePuncher();
    const b = new wrtc.HolePuncher();
    await a.start(0);
    await b.start(0);

    const gotPunch = new Promise(res => b.on('punch', (data, rinfo) => res(rinfo)));
    a.punch('127.0.0.1', b.localPort, 'peer-a');
    const rinfo = await gotPunch;
    if (rinfo.port !== a.localPort) throw new Error(`punch src port=${rinfo.port}`);
    if (!b.peers.has('peer-a')) throw new Error('B did not register peer from punch');

    await sleep(400); // 等 punch-ack
    if (!a.peers.has('peer-a')) throw new Error('A did not register its own peer id');

    // 双向数据
    const gotData = new Promise(res => a.on('ping', (data) => res(data)));
    b.send('peer-a', JSON.stringify({ type: 'ping', v: 1 }));
    const data = await gotData;
    if (data.v !== 1) throw new Error('payload mismatch');
    a.stop(); b.stop();
});

test('punch() after stop() does not throw async', async () => {
    let uncaught = null;
    const onUncaught = (e) => { uncaught = e; };
    process.on('uncaughtException', onUncaught);

    const hp = new wrtc.HolePuncher();
    await hp.start(0);
    hp.punch('127.0.0.1', 9999, 'ghost');
    hp.stop(); // 立刻停掉 socket
    await sleep(350); // punch 的 3 次 setTimeout 在此期间触发

    process.removeListener('uncaughtException', onUncaught);
    if (uncaught) throw new Error(`uncaught from stale punch timer: ${uncaught.message}`);
});

test('send()/sendTo() throw clear error after stop', async () => {
    const hp = new wrtc.HolePuncher();
    await hp.start(0);
    hp.peers.set('p', { address: '127.0.0.1', port: 1234 });
    hp.stop();
    let e1 = null, e2 = null;
    try { hp.send('p', 'x'); } catch (e) { e1 = e; }
    try { hp.sendTo('127.0.0.1', 1234, 'x'); } catch (e) { e2 = e; }
    if (!e1 || !/not started/.test(e1.message)) throw new Error('send error wrong: ' + e1);
    if (!e2 || !/not started/.test(e2.message)) throw new Error('sendTo error wrong: ' + e2);
});

(async () => {
    for (const [name, fn] of tests) {
        try {
            await fn();
            console.log('\u2713 ' + name);
            passed++;
        } catch (e) {
            console.log('\u2717 ' + name + ': ' + e.message);
            failed++;
        }
    }
    console.log(`\n=== hole-puncher.test: ${passed} passed, ${failed} failed ===`);
    process.exit(failed ? 1 : 0);
})();
