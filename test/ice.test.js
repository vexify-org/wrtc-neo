// ICE 候选解析 / 配对优先级 / SDP 回归测试
const wrtc = require('../index');

let passed = 0, failed = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);

// ---------- RTCIceCandidate 解析 ----------

test('RTCIceCandidate - standard parse with candidate: prefix', () => {
    const c = new wrtc.RTCIceCandidate({
        candidate: 'candidate:1 1 UDP 2130706431 192.168.1.5 5000 typ host',
        sdpMid: '0',
        sdpMLineIndex: 0
    });
    if (c.foundation !== '1') throw new Error(`foundation=${c.foundation} (prefix not stripped?)`);
    if (c.component !== 1) throw new Error(`component=${c.component}`);
    if (c.protocol !== 'udp') throw new Error(`protocol=${c.protocol}`);
    if (c.priority !== 2130706431) throw new Error(`priority=${c.priority}`);
    if (c.address !== '192.168.1.5') throw new Error(`address=${c.address}`);
    if (c.port !== 5000) throw new Error(`port=${c.port}`);
    if (c.candidateType !== 'host') throw new Error(`candidateType=${c.candidateType}`);
    if (c.type !== 'host') throw new Error(`type getter=${c.type}`);
    // 回归: sdpMLineIndex=0 不能被 || null 吞掉
    if (c.sdpMLineIndex !== 0) throw new Error(`sdpMLineIndex=${c.sdpMLineIndex} (0 must survive)`);
});

test('RTCIceCandidate - 8-part candidate without prefix parses', () => {
    const c = new wrtc.RTCIceCandidate({ candidate: '0 1 UDP 2130706431 192.168.1.1 12345 typ host' });
    if (c.port !== 12345) throw new Error(`port=${c.port}`);
    if (c.candidateType !== 'host') throw new Error(`candidateType=${c.candidateType}`);
    if (c.address !== '192.168.1.1') throw new Error(`address=${c.address}`);
});

test('RTCIceCandidate - a=candidate: prefix stripped too', () => {
    const c = new wrtc.RTCIceCandidate({ candidate: 'a=candidate:2 1 udp 100 10.0.0.1 4000 typ host' });
    if (c.foundation !== '2') throw new Error(`foundation=${c.foundation}`);
    if (c.candidateType !== 'host') throw new Error(`candidateType=${c.candidateType}`);
});

test('RTCIceCandidate - srflx with raddr/rport', () => {
    const c = new wrtc.RTCIceCandidate({
        candidate: 'candidate:2 1 udp 16777215 1.2.3.4 40000 typ srflx raddr 192.168.1.10 rport 40000'
    });
    if (c.candidateType !== 'srflx') throw new Error(`candidateType=${c.candidateType}`);
    if (c.relatedAddress !== '192.168.1.10') throw new Error(`relatedAddress=${c.relatedAddress}`);
    if (c.relatedPort !== 40000) throw new Error(`relatedPort=${c.relatedPort}`);
});

test('RTCIceCandidate - relay + tcptype', () => {
    const c = new wrtc.RTCIceCandidate({
        candidate: 'candidate:3 1 tcp 1509957119 10.0.0.1 7 typ relay raddr 10.0.0.2 rport 3478 tcptype active'
    });
    if (c.candidateType !== 'relay') throw new Error(`candidateType=${c.candidateType}`);
    if (c.protocol !== 'tcp') throw new Error(`protocol=${c.protocol}`);
    if (c.tcpType !== 'active') throw new Error(`tcpType=${c.tcpType}`);
});

test('RTCIceCandidate - isValid', () => {
    if (!wrtc.RTCIceCandidate.isValid('0 1 UDP 1 1.2.3.4 5 typ host')) throw new Error('valid string rejected');
    if (wrtc.RTCIceCandidate.isValid('candidate string')) throw new Error('garbage accepted');
    if (wrtc.RTCIceCandidate.isValid('')) throw new Error('empty accepted');
    if (wrtc.RTCIceCandidate.isValid('1 2 udp 3 4.5.6.7 8 9 host')) throw new Error('missing typ keyword accepted');
});

test('RTCIceCandidate - legacy {type: candidateStr} still works', () => {
    // ice-manager 旧内部约定，必须保持兼容
    const c = new wrtc.RTCIceCandidate({ type: 'candidate:1 1 UDP 2130706431 192.168.1.5 5000 typ srflx' });
    if (c.candidateType !== 'srflx') throw new Error(`candidateType=${c.candidateType}`);
});

// ---------- IceManager 配对优先级 ----------

function mkCandidate(priority, address, port, protocol = 'udp', candidateType = 'host') {
    return { foundation: '1', component: 1, protocol, priority, address, port, candidateType, type: candidateType };
}

test('IceManager - pair priority keeps BigInt precision for close values', () => {
    const mgr = new wrtc.IceManager([], null);
    mgr._role = 'controlling';
    // 两个本地候选优先级仅差 1，映射到 2^32*min(G,D) 后约 9.15e18，
    // 超出 Number.MAX_SAFE_INTEGER — 用 Number 计算会排序错乱
    mgr._localCandidates = [mkCandidate(2130706431, '10.0.0.1', 5001), mkCandidate(2130706430, '10.0.0.1', 5002)];
    mgr._remoteCandidates = [mkCandidate(2130706431, '10.0.0.2', 6000)];
    mgr._buildCheckList();

    if (mgr._checkList.length !== 2) throw new Error(`checkList size=${mgr._checkList.length}`);
    if (typeof mgr._checkList[0].sortKey !== 'bigint') throw new Error('sortKey should be BigInt');
    if (mgr._checkList[0].local.port !== 5001) throw new Error(`higher-priority pair sorted last (first port=${mgr._checkList[0].local.port})`);
});

test('IceManager - checklist only pairs same protocol', () => {
    const mgr = new wrtc.IceManager([], null);
    mgr._localCandidates = [mkCandidate(100, '10.0.0.1', 5000, 'udp')];
    mgr._remoteCandidates = [mkCandidate(100, '10.0.0.2', 6000, 'tcp')];
    mgr._buildCheckList();
    if (mgr._checkList.length !== 0) throw new Error(`cross-protocol pair created (${mgr._checkList.length})`);
});

test('IceManager - controlling role honors G/D assignment', () => {
    const mgr = new wrtc.IceManager([], null);
    mgr._role = 'controlling';
    const local = mkCandidate(300, '10.0.0.1', 5000);
    const remote = mkCandidate(200, '10.0.0.2', 6000);
    const p = mgr._calculatePairPriority(local, remote);
    // G=local(300) > D=remote(200): 2^32*200 + 2*300 + 1
    const expected = (200n << 32n) + 600n + 1n;
    if (p.big !== expected) throw new Error(`big=${p.big} expected=${expected}`);
});

// ---------- SDP 回归 ----------

test('SDP - offer contains exactly one a=setup / a=fingerprint', async () => {
    const pc = new wrtc.RTCPeerConnection();
    const offer = await pc.createOffer();
    const setups = (offer.sdp.match(/a=setup:/g) || []).length;
    const fps = (offer.sdp.match(/a=fingerprint:/g) || []).length;
    pc.close();
    if (setups !== 1) throw new Error(`a=setup appears ${setups} times`);
    if (fps !== 1) throw new Error(`a=fingerprint appears ${fps} times`);
    if (!/a=setup:actpass/.test(offer.sdp)) throw new Error('offer should be actpass');
});

test('SDP - answer uses setup:active', async () => {
    const pc = new wrtc.RTCPeerConnection();
    const answer = await pc.createAnswer();
    pc.close();
    if (!/a=setup:active/.test(answer.sdp)) throw new Error('answer should be active');
});

test('PC - setLocalDescription does NOT poison remote fingerprint', async () => {
    const pc = new wrtc.RTCPeerConnection();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const leaked = pc._remoteFingerprint;
    pc.close();
    if (leaked !== null && leaked !== undefined) {
        throw new Error(`local SDP fingerprint leaked into _remoteFingerprint: ${leaked}`);
    }
});

test('PC - _parseRemoteFingerprint reads remote SDP', () => {
    const pc = new wrtc.RTCPeerConnection();
    pc._parseRemoteFingerprint('v=0\r\na=fingerprint:sha-256 AB:CD:EF:00:11\r\n');
    pc.close();
    if (pc._remoteFingerprint !== 'AB:CD:EF:00:11') throw new Error(`fingerprint=${pc._remoteFingerprint}`);
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
    console.log(`\n=== ice.test: ${passed} passed, ${failed} failed ===`);
    process.exit(failed ? 1 : 0);
})();
