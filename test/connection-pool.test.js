// ConnectionPool 定时器泄漏 / 误重连回归测试
const { EventEmitter } = require('events');
const wrtc = require('../index');

let passed = 0, failed = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

class FakeConn extends EventEmitter {
    constructor(id) { super(); this.id = id; this.lastUsed = Date.now(); this.closed = false; }
    send() { return true; }
    close() { this.closed = true; this.emit('close'); }
}

test('_waitForConnection resolves when connection appears, interval cleared', async () => {
    const pool = new wrtc.ConnectionPool({ autoReconnect: false });
    pool.pendingConnections.add('stuck');
    const p = pool._waitForConnection('stuck');
    await sleep(250);
    pool.connections.set('stuck', new FakeConn('stuck'));
    pool.pendingConnections.delete('stuck');
    const conn = await p;
    if (!conn || conn.id !== 'stuck') throw new Error('did not resolve with created connection');
    // resolve 后 interval 必须已清;若泄漏,本文件末尾进程会挂住不退出

    // 失败路径: pending 消失且无连接 → reject
    pool.pendingConnections.add('doomed');
    const p2 = pool._waitForConnection('doomed');
    await sleep(150);
    pool.pendingConnections.delete('doomed');
    let err = null;
    await p2.catch(e => { err = e; });
    if (!err || !/Connection failed/.test(err.message)) throw new Error('failed path did not reject: ' + err);
    pool.closeAll();
});

test('_cleanupOldConnections does not trigger auto-reconnect', async () => {
    let reconnects = 0;
    const pool = new wrtc.ConnectionPool({
        maxConnections: 2,
        minConnections: 1,
        autoReconnect: true,
        connectionFactory: async (id) => new FakeConn(id)
    });
    pool.on('reconnecting', () => reconnects++);

    const a = await pool.getConnection('a');
    await sleep(1100); // 拉开 lastUsed
    const b = await pool.getConnection('b');
    await sleep(1100);
    const c = await pool.getConnection('c'); // 触发 cleanup 淘汰最旧的 a

    await sleep(400);
    if (pool.connections.has('a')) throw new Error('oldest connection was not evicted');
    if (reconnects > 0) throw new Error(`cleanup triggered ${reconnects} reconnect(s)`);
    pool.closeAll();
});

test('closeConnection does not auto-reconnect; unexpected drop does', async () => {
    let reconnects = 0;
    const pool = new wrtc.ConnectionPool({
        autoReconnect: true,
        reconnectDelay: 50,
        connectionFactory: async (id) => new FakeConn(id)
    });
    pool.on('reconnecting', () => reconnects++);

    const conn = await pool.getConnection('x');
    pool.closeConnection('x');
    await sleep(250);
    if (reconnects > 0) throw new Error(`closeConnection triggered reconnect (${reconnects})`);

    // 模拟意外断线
    const conn2 = await pool.getConnection('y');
    conn2.emit('close');
    await sleep(250);
    if (reconnects === 0) throw new Error('unexpected drop did not schedule reconnect');
    pool.closeAll();
});

test('ping treats send() returning undefined as success (not packet loss)', async () => {
    const pool = new wrtc.ConnectionPool({ pingInterval: 60, autoReconnect: false });
    const conn = new FakeConn('z');
    conn.send = () => undefined; // hole-puncher 风格: 无返回值
    pool.connections.set('z', conn);
    pool._quality.set('z', new wrtc.ConnectionQuality());
    pool._startPing('z', conn);
    await sleep(250);
    pool._stopPing('z');
    const q = pool.getQuality('z');
    pool.closeAll();
    if (q.packetLoss !== '0.0%') throw new Error(`falsy send counted as loss: ${q.packetLoss}`);
});

test('ReconnectBuffer evicts oldest within maxMessages', () => {
    const buf = new wrtc.ReconnectBuffer({ maxMessages: 3, maxSize: 1e6 });
    for (let i = 0; i < 5; i++) buf.push({ i });
    if (buf.count !== 3) throw new Error(`count=${buf.count}`);
    const drained = buf.drain();
    if (drained[0].message.i !== 2 || drained[2].message.i !== 4) throw new Error('wrong eviction order');
    if (buf.count !== 0 || buf.size !== 0) throw new Error('drain did not reset');
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
    console.log(`\n=== connection-pool.test: ${passed} passed, ${failed} failed ===`);
    if (failed) process.exit(1);
    // 若仍有未清理的 interval/timer,进程会挂住 — 自然验证泄漏修复
    setTimeout(() => {}, 50).unref?.();
})();
