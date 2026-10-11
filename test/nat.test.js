// NAT 类型检测测试 — 本地 mock STUN 服务器，验证判定矩阵
const dgram = require('dgram');
const wrtc = require('../index');

let passed = 0, failed = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);

const MAGIC = 0x2112a442;
const T = wrtc.NatDetector.NAT_TYPES;

function buildResponse(tid, address, port) {
    const resp = Buffer.alloc(32);
    resp.writeUInt16BE(0x0101, 0);
    resp.writeUInt16BE(12, 2);
    resp.writeUInt32BE(MAGIC, 4);
    tid.copy(resp, 8);
    const ip = address.split('.').map(Number);
    resp.writeUInt16BE(0x0020, 20); // XOR-MAPPED-ADDRESS
    resp.writeUInt16BE(8, 22);
    resp.writeUInt8(0, 24);
    resp.writeUInt8(1, 25);
    resp.writeUInt16BE(port ^ 0x2112, 26);
    resp.writeUInt8(ip[0] ^ 0x21, 28);
    resp.writeUInt8(ip[1] ^ 0x12, 29);
    resp.writeUInt8(ip[2] ^ 0xa4, 30);
    resp.writeUInt8(ip[3] ^ 0x42, 31);
    return resp;
}

// mock STUN(主 socket 端口 P + 孪生 socket 端口 P+1,支持 Test II 的 changePort):
//   behavior 'fixed'     → 两个 socket 返回同一映射
//   behavior 'symmetric' → 映射随服务器端口变化(不同服务器/端口得到不同映射)
//   changeRequestSupport → 响应 CHANGE-REQUEST:
//        change-port → 从孪生 socket(不同源端口)回包到客户端监听端口
//        change-ip   → 从 127.0.0.2 的 socket 回包(不同源 IP)
//   dropToChangedIp → 丢弃 change-ip 请求(Test IV 失败 / Test V 成功 → RESTRICTED)
function startMockStun(options = {}) {
    const {
        behavior = 'fixed',
        changeRequestSupport = false,
        mappedIp = '203.0.113.9',
        fixedMappedPort = 40000,
        dropToChangedIp = false
    } = options;

    return new Promise((resolve) => {
        const sockets = [];
        let altIpSock = null;
        const getAltIpSock = (cb) => {
            if (altIpSock) return cb(altIpSock);
            altIpSock = dgram.createSocket('udp4');
            altIpSock.bind(0, '127.0.0.2', () => cb(altIpSock));
        };

        const makeHandler = (sock, tag) => (msg, rinfo) => {
            if (msg.length < 20) return;
            if (msg.readUInt16BE(0) !== 0x0001) return;
            const tid = msg.slice(8, 20);

            let changeReq = 0;
            let offset = 20;
            while (offset + 4 <= msg.length) {
                const aType = msg.readUInt16BE(offset);
                const aLen = msg.readUInt16BE(offset + 2);
                if (offset + 4 + aLen > msg.length) break;
                if (aType === 0x0003 && aLen >= 4) changeReq = msg.readUInt32BE(offset + 4);
                offset += 4 + aLen + ((4 - (aLen % 4)) % 4);
            }

            if (changeReq) {
                if (!changeRequestSupport) return; // 现代服务器普遍忽略 CHANGE-REQUEST
                const changeIp = (changeReq & 0x4) !== 0;
                if (changeIp && dropToChangedIp) return;
                const reply = (src) => {
                    try { src.send(buildResponse(tid, mappedIp, fixedMappedPort), rinfo.port, '127.0.0.1'); } catch (e) {}
                };
                if (changeIp) getAltIpSock(reply); else reply(sock);
                return;
            }

            const mappedPort = behavior === 'symmetric' ? (fixedMappedPort + tag * 1000 + sock.address().port) % 60000 + 1024 : fixedMappedPort;
            sock.send(buildResponse(tid, mappedIp, mappedPort), rinfo.port, rinfo.address);
        };

        const main = dgram.createSocket('udp4');
        main.on('message', makeHandler(main, 0));
        main.bind(0, '127.0.0.1', () => {
            const mainPort = main.address().port;
            const sibling = dgram.createSocket('udp4');
            sibling.on('message', makeHandler(sibling, 1));
            sibling.bind(mainPort + 1, '127.0.0.1', () => {
                sockets.push(main, sibling);
                resolve({
                    port: mainPort,
                    host: '127.0.0.1',
                    close: () => {
                        for (const s of sockets) { try { s.close(); } catch (e) {} }
                        if (altIpSock) { try { altIpSock.close(); } catch (e) {} }
                    }
                });
            });
        });
    });
}

function makeDetector(s1, s2) {
    return new wrtc.NatDetector({
        stunServer1: { host: s1.host, port: s1.port },
        stunServer2: { host: s2.host, port: s2.port },
        timeout: 600
    });
}

test('no STUN response → BLOCKED', async () => {
    const s2 = await startMockStun({});
    const det = makeDetector({ host: '127.0.0.1', port: 1 }, s2); // 端口 1 无服务
    const r = await det.detect();
    s2.close();
    if (r.type !== T.BLOCKED) throw new Error(`type=${r.type}`);
});

test('consistent mapping, no change-request support → PORT_RESTRICTED', async () => {
    const s1 = await startMockStun({ behavior: 'fixed', changeRequestSupport: false });
    const s2 = await startMockStun({ behavior: 'fixed', changeRequestSupport: false });
    const det = makeDetector(s1, s2);
    const r = await det.detect();
    s1.close(); s2.close();
    // 映射一致但服务器忽略 CHANGE-REQUEST → 无法证明 full-cone,保守判 port-restricted
    if (r.type !== T.PORT_RESTRICTED) throw new Error(`type=${r.type}`);
    if (r.publicAddress !== '203.0.113.9') throw new Error(`publicAddress=${r.publicAddress}`);
    if (r.publicPort !== 40000) throw new Error(`publicPort=${r.publicPort}`);
});

test('consistent mapping + change-request answered → FULL_CONE', async () => {
    const s1 = await startMockStun({ behavior: 'fixed', changeRequestSupport: true });
    const s2 = await startMockStun({ behavior: 'fixed', changeRequestSupport: true });
    const det = makeDetector(s1, s2);
    const r = await det.detect();
    s1.close(); s2.close();
    if (r.type !== T.FULL_CONE) throw new Error(`type=${r.type}`);
});

test('change-ip dropped but change-port answered → RESTRICTED', async () => {
    const s1 = await startMockStun({ behavior: 'fixed', changeRequestSupport: true, dropToChangedIp: true });
    const s2 = await startMockStun({ behavior: 'fixed', changeRequestSupport: true, dropToChangedIp: true });
    const det = makeDetector(s1, s2);
    const r = await det.detect();
    s1.close(); s2.close();
    if (r.type !== T.RESTRICTED) throw new Error(`type=${r.type}`);
});

test('mapping changes per destination port → SYMMETRIC / SYMMETRIC_FIREWALL', async () => {
    const s1 = await startMockStun({ behavior: 'symmetric' });
    const s2 = await startMockStun({ behavior: 'symmetric' });
    const det = makeDetector(s1, s2);
    const r = await det.detect();
    s1.close(); s2.close();
    if (r.type !== T.SYMMETRIC && r.type !== T.SYMMETRIC_FIREWALL) throw new Error(`type=${r.type}`);
});

test('socket reuse regression: fixed servers never misjudged as SYMMETRIC', async () => {
    // 回归:旧实现每个 test 新建 socket → 源端口变化 → 映射比较失效 → 恒判 SYMMETRIC。
    // 新实现复用 socket:同一组 fixed 服务器必须给出稳定非对称判定。
    const s1 = await startMockStun({ behavior: 'fixed', changeRequestSupport: true });
    const s2 = await startMockStun({ behavior: 'fixed', changeRequestSupport: true });
    const det = makeDetector(s1, s2);
    const r = await det.detect();
    const r2 = await det.detect();
    s1.close(); s2.close();
    if (r.type === T.SYMMETRIC || r.type === T.SYMMETRIC_FIREWALL) throw new Error(`misjudged: ${r.type}`);
    if (r.type !== r2.type) throw new Error(`unstable verdict: ${r.type} vs ${r2.type}`);
});

test('quickDetect: fixed mapping → FULL_CONE with public addr', async () => {
    const s1 = await startMockStun({ behavior: 'fixed' });
    const s2 = await startMockStun({ behavior: 'fixed' });
    const det = makeDetector(s1, s2);
    const r = await det.quickDetect();
    s1.close(); s2.close();
    if (r.type !== T.FULL_CONE) throw new Error(`type=${r.type}`);
    if (r.publicPort !== 40000) throw new Error(`publicPort=${r.publicPort}`);
});

test('malformed responses never crash detector', async () => {
    const sock = dgram.createSocket('udp4');
    sock.on('message', (msg, rinfo) => {
        try {
            sock.send(Buffer.from([0x01, 0x01]), rinfo.port, rinfo.address); // 太短
            sock.send(Buffer.alloc(20, 0xab), rinfo.port, rinfo.address);    // 乱码
            const tid = msg.length >= 20 ? msg.slice(8, 20) : Buffer.alloc(12);
            const r = buildResponse(tid, '1.2.3.4', 7000);
            sock.send(r.subarray(0, 24), rinfo.port, rinfo.address);         // 属性截断
        } catch (e) {}
    });
    await new Promise(r => sock.bind(0, '127.0.0.1', r));
    const s2 = await startMockStun({});

    let uncaught = null;
    const onU = (e) => { uncaught = e; };
    process.on('uncaughtException', onU);

    const det = new wrtc.NatDetector({
        stunServer1: { host: '127.0.0.1', port: sock.address().port },
        stunServer2: { host: '127.0.0.1', port: s2.port },
        timeout: 400
    });
    const r = await det.detect();

    process.removeListener('uncaughtException', onU);
    sock.close(); s2.close();
    if (uncaught) throw new Error(`crashed: ${uncaught.message}`);
    if (!r.type) throw new Error('no verdict returned');
});

test('NAT_TYPES constants exported', () => {
    for (const k of ['OPEN', 'FULL_CONE', 'RESTRICTED', 'PORT_RESTRICTED', 'SYMMETRIC', 'BLOCKED']) {
        if (!T[k]) throw new Error(`missing NAT_TYPES.${k}`);
    }
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
    console.log(`\n=== nat.test: ${passed} passed, ${failed} failed ===`);
    process.exit(failed ? 1 : 0);
})();
