#!/usr/bin/env node
const pkg = require('../package.json');
const wrtc = require('../index');

console.log(`WRTC Neo v${pkg.version}`);
console.log('Copyright (c) Vexify 2026');
console.log('');
console.log('Exports:');
console.log('  - RTCPeerConnection');
console.log('  - RTCDataChannel');
console.log('  - RTCSessionDescription');
console.log('  - RTCIceCandidate');
console.log('');
console.log('Usage:');
console.log('  const wrtc = require("wrtc-neo");');
console.log('  const pc = new wrtc.RTCPeerConnection({ iceServers: [...] });');
