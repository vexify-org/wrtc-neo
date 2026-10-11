const wrtc = require('../index');

console.log('=== WRTC Neo Basic Tests ===\n');

let passed = 0;
let failed = 0;

const test = (name, fn) => {
    try {
        fn();
        console.log(`✓ ${name}`);
        passed++;
    } catch (error) {
        console.log(`✗ ${name}: ${error.message}`);
        failed++;
    }
};

test('RTCSessionDescription - Create with valid type', () => {
    const desc = new wrtc.RTCSessionDescription({ type: 'offer', sdp: 'test' });
    if (desc.type !== 'offer') throw new Error('Type should be offer');
    if (desc.sdp !== 'test') throw new Error('SDP should be test');
});

test('RTCSessionDescription - toJSON', () => {
    const desc = new wrtc.RTCSessionDescription({ type: 'answer', sdp: 'sdp content' });
    const json = desc.toJSON();
    if (json.type !== 'answer') throw new Error('JSON type should be answer');
    if (json.sdp !== 'sdp content') throw new Error('JSON SDP should match');
});

test('RTCIceCandidate - Create with valid data', () => {
    const candidate = new wrtc.RTCIceCandidate({
        candidate: '0 1 UDP 2130706431 192.168.1.1 12345 typ host',
        sdpMid: '0',
        sdpMLineIndex: 0
    });
    if (!candidate.candidate) throw new Error('Candidate should have candidate string');
});

test('RTCIceCandidate - toJSON', () => {
    const candidate = new wrtc.RTCIceCandidate({
        candidate: 'candidate string',
        sdpMid: '0',
        sdpMLineIndex: 0
    });
    const json = candidate.toJSON();
    if (json.candidate !== 'candidate string') throw new Error('JSON candidate should match');
});

test('RTCPeerConnection - Create with config', () => {
    const pc = new wrtc.RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }]
    });
    if (pc.connectionState !== 'new') throw new Error('Initial state should be new');
    pc.close();
});

test('RTCPeerConnection - createOffer', async () => {
    const pc = new wrtc.RTCPeerConnection();
    const offer = await pc.createOffer();
    if (!(offer instanceof wrtc.RTCSessionDescription)) throw new Error('Should return RTCSessionDescription');
    if (offer.type !== 'offer') throw new Error('Offer type should be offer');
    if (!offer.sdp) throw new Error('Offer should have SDP');
    pc.close();
});

test('RTCPeerConnection - createAnswer', async () => {
    const pc = new wrtc.RTCPeerConnection();
    const answer = await pc.createAnswer();
    if (!(answer instanceof wrtc.RTCSessionDescription)) throw new Error('Should return RTCSessionDescription');
    if (answer.type !== 'answer') throw new Error('Answer type should be answer');
    pc.close();
});

test('RTCPeerConnection - setLocalDescription', async () => {
    const pc = new wrtc.RTCPeerConnection();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    if (!pc.localDescription) throw new Error('Local description should be set');
    pc.close();
});

test('RTCPeerConnection - createDataChannel', () => {
    const pc = new wrtc.RTCPeerConnection();
    const dc = pc.createDataChannel('test');
    if (dc.label !== 'test') throw new Error('DataChannel label should be test');
    if (dc.readyState !== 'connecting') throw new Error('Initial readyState should be connecting');
    pc.close();
});

test('RTCDataChannel - Event listeners', () => {
    const pc = new wrtc.RTCPeerConnection();
    const dc = pc.createDataChannel('events');
    
    let openCalled = false;
    dc.on('open', () => { openCalled = true; });
    
    dc._emit('open');
    
    if (!openCalled) throw new Error('Open event should be emitted');
    
    pc.close();
});

console.log('\n=== Test Results ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed === 0) {
    console.log('\n✓ All tests passed!');
    process.exit(0);
} else {
    console.log('\n✗ Some tests failed');
    process.exit(1);
}