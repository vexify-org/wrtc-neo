// ReliableChannel 重传机制 + MessageBuffer 测试
const { EventEmitter } = require('events');
const wrtc = require('../index');

let passed = 0, failed = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// 模拟 RTCDataChannel: EventEmitter + send 记录
class FakeChannel extends EventEmitter {
    constructor() {
        super();
        this.sent = [];
        this.readyState = 'open';
        this.closed = false;
        this.blocked = false; // send 返回 false 模拟背压
    }
    send(data) {
        if (this.blocked) return false;
        this.sent.push(data);
        return true;
    }
    close() { this.closed = true; this.readyState = 'closed'; }
    get bufferedAmount() { return 0; }
    // 模拟收到对端消息
    inject(data) { this.emit('message', { data: typeof data === 'string' ? data : JSON.stringify(data) }); }
}

function openChannel() {
    const ch = new FakeChannel();
    const rc = new wrtc.ReliableChannel(ch, { ackTimeout: 50, maxRetries: 3, retryDelay: 10 });
    rc._isOpen = true;
    return { ch, rc };
}

test('ReliableChannel - send queues ack pending and clears on ack', async () => {
    const { ch, rc } = openChannel();
    rc.send('hello');
    if (ch.sent.length !== 1) throw new Error(`sent=${ch.sent.length}`);
    if (rc._pendingMessages.size !== 1) throw new Error('pending not tracked');

    const parsed = JSON.parse(ch.sent[0]);
    ch.inject({ type: 'ack', sequence: parsed.sequence });
    if (rc._pendingMessages.size !== 0) throw new Error('ack did not clear pending');
    rc.close();
});

test('ReliableChannel - dedup duplicates by sequence', async () => {
    const { ch, rc } = openChannel();
    let received = 0;
    rc.on('message', () => received++);
    const msg = { type: 'data', sequence: 42, data: 'x' };
    ch.inject(msg);
    ch.inject(msg);
    ch.inject(msg);
    if (received !== 1) throw new Error(`duplicate delivered: received=${received}`);
    rc.close();
});

test('ReliableChannel - retry then exhaust emits retryExhausted', async () => {
    const { ch, rc } = openChannel();
    rc.send('lost');
    let exhausted = null;
    rc.on('retryExhausted', (e) => { exhausted = e; });
    // ackTimeout=50, attempts 1..3 → 全部超时
    await sleep(400);
    if (!exhausted) throw new Error('retryExhausted not emitted');
    if (rc._pendingMessages.size !== 0) throw new Error('pending leaked after exhaustion');
    rc.close();
});

test('ReliableChannel - retry succeeds when ack arrives late', async () => {
    const { ch, rc } = openChannel();
    rc.send('slow-ack');
    const parsed = JSON.parse(ch.sent[0]);
    await sleep(80); // 第一次超时,触发重发
    if (ch.sent.length < 2) throw new Error('no retransmission happened');
    ch.inject({ type: 'ack', sequence: parsed.sequence });
    if (rc._pendingMessages.size !== 0) throw new Error('late ack did not clear pending');
    rc.close();
});

test('ReliableChannel - close during pending does not throw / no ghost timers', async () => {
    const { ch, rc } = openChannel();
    rc.send('a');
    rc.send('b');
    rc.close();
    if (rc._pendingMessages.size !== 0) throw new Error('pending not cleared on close');
    await sleep(150); // 幽灵定时器会在 _retryMessage 里炸
});

test('ReliableChannel - queued messages flush on open', async () => {
    const ch = new FakeChannel();
    const rc = new wrtc.ReliableChannel(ch, { ackTimeout: 50 });
    rc.send('q1');
    rc.send('q2');
    if (ch.sent.length !== 0) throw new Error('sent while closed');
    if (rc._messageQueue.length !== 2) throw new Error(`queue=${rc._messageQueue.length}`);
    ch.emit('open');
    if (ch.sent.length !== 2) throw new Error(`queue not flushed: sent=${ch.sent.length}`);
    rc.close();
});

test('ReliableChannel - retry after channel reopen re-queues (no silent loss)', async () => {
    const { ch, rc } = openChannel();
    rc.send('must-not-lose');
    const parsed = JSON.parse(ch.sent[0]);
    // 模拟信道断开
    ch.emit('close');
    await sleep(120); // 至少一次超时重试发生在关闭期间
    if (rc._pendingMessages.has(parsed.sequence)) throw new Error('still pending while closed');
    // 重开 → 消息应重新排队并再次发出(同一 sequence 的 data 共 2 条:原始+重发)
    ch.emit('open');
    const count = ch.sent.filter(s => { const m = JSON.parse(s); return m.sequence === parsed.sequence && m.type === 'data'; }).length;
    if (count < 2) throw new Error(`message silently dropped during reopen (data sends for seq=${parsed.sequence}: ${count})`);
    rc.close();
});

test('ReliableChannel - maxDedupSize bounds memory', async () => {
    const ch = new FakeChannel();
    const rc = new wrtc.ReliableChannel(ch, { maxDedupSize: 10, enableAck: false });
    rc._isOpen = true;
    for (let i = 0; i < 100; i++) {
        ch.inject({ type: 'data', sequence: i, data: 'x' });
    }
    if (rc._receivedMessages.size > 10) throw new Error(`dedup set grew to ${rc._receivedMessages.size}`);
    rc.close();
});

// ---------- MessageBuffer ----------

test('MessageBuffer - highWaterMark fires on BYTES not count', async () => {
    const buf = new wrtc.MessageBuffer({ maxSize: 100 });
    let hi = false;
    buf.on('highWaterMark', () => { hi = true; });
    // 3 条 ~40 字节的报文 → 总量超过 50 字节(=maxSize/2) 应触发
    buf.add({ payload: 'x'.repeat(40) });
    if (!hi) throw new Error('highWaterMark not fired at byte threshold');
});

test('MessageBuffer - eviction keeps total under maxSize', async () => {
    const buf = new wrtc.MessageBuffer({ maxSize: 120 });
    const evicted = [];
    buf.on('evicted', (m) => evicted.push(m));
    for (let i = 0; i < 10; i++) buf.add({ i, payload: 'y'.repeat(30) });
    if (buf.size > 120) throw new Error(`size=${buf.size} > maxSize`);
    if (evicted.length === 0) throw new Error('nothing evicted');
});

test('MessageBuffer - get(size) accounts totalSize', async () => {
    const buf = new wrtc.MessageBuffer({ maxSize: 10000 });
    buf.add({ a: 'xx' });
    buf.add({ b: 'yy' });
    const before = buf.size;
    buf.get(1);
    if (buf.size >= before) throw new Error(`size not decreased: ${before} -> ${buf.size}`);
});

// ---------- runner ----------
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
    console.log(`\n=== reliable-channel.test: ${passed} passed, ${failed} failed ===`);
    process.exit(failed ? 1 : 0);
})();
