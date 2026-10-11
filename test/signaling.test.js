// SignalingClient 测试 — 本地 ws 服务器验证连接/重连/心跳/消息
const { WebSocketServer } = require('ws');
const wrtc = require('../index');

let passed = 0, failed = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function startServer(opts = {}) {
    return new Promise((resolve) => {
        // 先建裸 http 再 attach wss,显式在 listening 后取端口(避免 'listening' 已过时机的竞态)
        const http = require('http');
        const server = http.createServer();
        const wss = new WebSocketServer({ server });
        const state = { sockets: [], wss };
        wss.on('connection', (ws) => {
            state.sockets.push(ws);
            if (opts.onConnection) opts.onConnection(ws, state);
        });
        server.listen(0, '127.0.0.1', () => resolve({
            ...state,
            port: server.address().port,
            url: `ws://127.0.0.1:${server.address().port}`,
            close: () => new Promise((res) => {
                for (const s of state.sockets) { try { s.terminate(); } catch (e) {} }
                wss.close(() => server.close(res));
            })
        }));
    });
}

function waitOpen(client, ms = 2000) {
    return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('open timeout')), ms);
        client.on('open', () => { clearTimeout(t); resolve(); });
        client.connect(); // 幂等:OPEN/CONNECTING 状态下重复调用无副作用
    });
}

test('connect + JSON message roundtrip', async () => {
    const srv = await startServer({ onConnection: (ws) => {
        ws.on('message', (m) => ws.send(m.toString()));
    }});
    const sc = new wrtc.SignalingClient(srv.url, { peerId: 'me' });
    await waitOpen(sc);
    if (!sc.connected) throw new Error('connected flag false');

    const got = new Promise(res => sc.on('message', res));
    sc.send({ hello: 'world' });
    const msg = await got;
    if (!msg || msg.hello !== 'world') throw new Error(`echo=${JSON.stringify(msg)}`);
    sc.disconnect();
    await srv.close();
});

test('connect() while CONNECTING does not create a second socket', async () => {
    const srv = await startServer({});
    const sc = new wrtc.SignalingClient(srv.url);
    sc.connect();
    sc.connect(); // 第二次调用应被忽略
    sc.connect();
    await waitOpen(sc);
    await sleep(150);
    if (srv.sockets.length !== 1) throw new Error(`server saw ${srv.sockets.length} sockets (duplicate WS created)`);
    sc.disconnect();
    await srv.close();
});

test('close with undefined reason does not throw', async () => {
    const srv = await startServer({});
    const sc = new wrtc.SignalingClient(srv.url, { maxReconnectAttempts: 0 });
    await waitOpen(sc);
    let closeInfo = null;
    sc.on('close', (info) => { closeInfo = info; });
    // 服务器直接 terminate → close 事件的 reason 参数为 undefined
    srv.sockets[0].terminate();
    await sleep(300);
    if (!closeInfo) throw new Error('close not emitted');
    if (typeof closeInfo.reason !== 'string') throw new Error(`reason not string: ${closeInfo.reason}`);
    sc.disconnect();
    await srv.close();
});

test('intentional disconnect() does not trigger reconnect', async () => {
    const srv = await startServer({});
    const sc = new wrtc.SignalingClient(srv.url, { reconnectInterval: 50, maxReconnectAttempts: 5 });
    await waitOpen(sc);
    sc.disconnect();
    await sleep(300);
    if (srv.sockets.length !== 1) throw new Error(`reconnected after intentional disconnect (${srv.sockets.length} sockets)`);
    await srv.close();
});

test('auto-reconnect after server drop', async () => {
    const srv = await startServer({});
    const sc = new wrtc.SignalingClient(srv.url, { reconnectInterval: 60, maxReconnectAttempts: 3 });
    await waitOpen(sc);

    let reopened = false;
    sc.on('open', () => { reopened = true; });

    // 服务器强制掉线(无正常 close 帧)
    srv.sockets[0].terminate();
    await sleep(600);
    if (!reopened) throw new Error('did not reconnect after server drop');
    if (!sc.connected) throw new Error('connected flag not restored');
    sc.disconnect();
    await srv.close();
});

test('sendOffer/sendAnswer/sendIceCandidate envelope format', async () => {
    const received = [];
    const srv = await startServer({ onConnection: (ws) => {
        ws.on('message', (m) => received.push(JSON.parse(m.toString())));
    }});
    const sc = new wrtc.SignalingClient(srv.url, { peerId: 'alice' });
    await waitOpen(sc);
    sc.sendOffer('bob', { sdp: 'x' });
    sc.sendAnswer('bob', { sdp: 'y' });
    sc.sendIceCandidate('bob', { candidate: 'c' });
    await sleep(150);
    sc.disconnect();
    await srv.close();
    if (received.length !== 3) throw new Error(`received=${received.length}`);
    if (received[0].type !== 'offer' || received[0].from !== 'alice' || received[0].to !== 'bob') throw new Error('offer envelope wrong');
    if (received[1].type !== 'answer') throw new Error('answer type wrong');
    if (received[2].type !== 'ice_candidate') throw new Error('ice type wrong');
});

test('send() throws when not connected', () => {
    const sc = new wrtc.SignalingClient('ws://127.0.0.1:1');
    let e = null;
    try { sc.send({ a: 1 }); } catch (err) { e = err; }
    if (!e || !/Not connected/.test(e.message)) throw new Error('no clear error: ' + e);
});

test('ping heartbeat keeps connection alive', async () => {
    const received = [];
    const srv = await startServer({ onConnection: (ws) => {
        ws.on('message', (m) => received.push(m.toString()));
    }});
    const sc = new wrtc.SignalingClient(srv.url, { pingInterval: 80 });
    await waitOpen(sc);
    await sleep(260);
    sc.disconnect();
    await srv.close();
    const keepalives = received.filter(r => r.includes('keep_alive'));
    if (keepalives.length < 2) throw new Error(`expected >=2 keep_alive, got ${keepalives.length}`);
});

test('disconnect() while CONNECTING terminates handshake cleanly', async () => {
    // 连接一个黑洞端口(accept 但不响应 handshake)不可行;用慢服务器:接受 TCP 但 ws handshake 延迟
    const net = require('net');
    const blackhole = net.createServer((sock) => { /* 不发 HTTP 101,ws 一直 CONNECTING */ });
    await new Promise(r => blackhole.listen(0, '127.0.0.1', r));
    const port = blackhole.address().port;

    const sc = new wrtc.SignalingClient(`ws://127.0.0.1:${port}`, { maxReconnectAttempts: 0 });
    let uncaught = null;
    const onU = (e) => { uncaught = e; };
    process.on('uncaughtException', onU);

    sc.connect();       // CONNECTING 状态
    sc.disconnect();    // 应立即 terminate,而不是排队 close 后报错
    await sleep(300);
    process.removeListener('uncaughtException', onU);
    blackhole.close();
    if (uncaught) throw new Error(`uncaught: ${uncaught.message}`);
    if (sc.connected) throw new Error('still connected');
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
    console.log(`\n=== signaling.test: ${passed} passed, ${failed} failed ===`);
    process.exit(failed ? 1 : 0);
})();
