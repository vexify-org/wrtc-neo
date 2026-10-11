class SdpParser {
    static parse(sdp) {
        const lines = sdp.trim().split(/\r\n|\r|\n/);
        const result = {
            version: 0,
            origin: null,
            sessionName: '',
            timing: null,
            attributes: [],
            media: []
        };

        let currentMedia = null;

        for (const line of lines) {
            if (!line || !line.includes('=')) continue;
            
            const [type, value] = line.split('=', 2);

            switch (type) {
                case 'v':
                    result.version = parseInt(value, 10);
                    break;
                
                case 'o':
                    result.origin = this._parseOrigin(value);
                    break;
                
                case 's':
                    result.sessionName = value;
                    break;
                
                case 't':
                    result.timing = this._parseTiming(value);
                    break;
                
                case 'a':
                    if (currentMedia) {
                        currentMedia.attributes.push(this._parseAttribute(value));
                    } else {
                        result.attributes.push(this._parseAttribute(value));
                    }
                    break;
                
                case 'm':
                    if (currentMedia) {
                        result.media.push(currentMedia);
                    }
                    currentMedia = this._parseMedia(value);
                    break;
                
                case 'c':
                    if (currentMedia) {
                        currentMedia.connection = this._parseConnection(value);
                    }
                    break;
                
                case 'u':
                    if (currentMedia) {
                        currentMedia.uri = value;
                    }
                    break;
                
                case 'e':
                    result.email = value;
                    break;
                
                case 'p':
                    result.phone = value;
                    break;
                
                case 'i':
                    if (currentMedia) {
                        currentMedia.information = value;
                    } else {
                        result.information = value;
                    }
                    break;
                
                case 'z':
                    result.timezone = value;
                    break;
                
                case 'k':
                    if (currentMedia) {
                        currentMedia.encryption = this._parseEncryption(value);
                    } else {
                        result.encryption = this._parseEncryption(value);
                    }
                    break;
            }
        }

        if (currentMedia) {
            result.media.push(currentMedia);
        }

        return result;
    }

    static stringify(parsed) {
        const lines = [];

        lines.push(`v=${parsed.version}`);
        
        if (parsed.origin) {
            lines.push(`o=${this._stringifyOrigin(parsed.origin)}`);
        }
        
        lines.push(`s=${parsed.sessionName}`);
        
        if (parsed.information) {
            lines.push(`i=${parsed.information}`);
        }
        
        if (parsed.email) {
            lines.push(`e=${parsed.email}`);
        }
        
        if (parsed.phone) {
            lines.push(`p=${parsed.phone}`);
        }
        
        if (parsed.timing) {
            lines.push(`t=${this._stringifyTiming(parsed.timing)}`);
        }
        
        if (parsed.timezone) {
            lines.push(`z=${parsed.timezone}`);
        }
        
        if (parsed.encryption) {
            lines.push(`k=${this._stringifyEncryption(parsed.encryption)}`);
        }
        
        for (const attr of parsed.attributes) {
            lines.push(`a=${this._stringifyAttribute(attr)}`);
        }
        
        for (const media of parsed.media) {
            lines.push(`m=${this._stringifyMedia(media)}`);
            
            if (media.information) {
                lines.push(`i=${media.information}`);
            }
            
            if (media.connection) {
                lines.push(`c=${this._stringifyConnection(media.connection)}`);
            }
            
            if (media.uri) {
                lines.push(`u=${media.uri}`);
            }
            
            if (media.encryption) {
                lines.push(`k=${this._stringifyEncryption(media.encryption)}`);
            }
            
            for (const attr of media.attributes) {
                lines.push(`a=${this._stringifyAttribute(attr)}`);
            }
        }

        return lines.join('\r\n') + '\r\n';
    }

    static _parseOrigin(value) {
        const parts = value.split(' ');
        return {
            username: parts[0],
            sessionId: parts[1],
            sessionVersion: parts[2],
            netType: parts[3],
            addrType: parts[4],
            unicastAddress: parts[5]
        };
    }

    static _stringifyOrigin(origin) {
        return `${origin.username} ${origin.sessionId} ${origin.sessionVersion} ${origin.netType} ${origin.addrType} ${origin.unicastAddress}`;
    }

    static _parseTiming(value) {
        const parts = value.split(' ');
        return {
            start: parseInt(parts[0], 10),
            stop: parseInt(parts[1], 10)
        };
    }

    static _stringifyTiming(timing) {
        return `${timing.start} ${timing.stop}`;
    }

    static _parseAttribute(value) {
        if (value.includes(':')) {
            const [key, attrValue] = value.split(':', 2);
            return { key, value: attrValue };
        }
        return { key: value, value: null };
    }

    static _stringifyAttribute(attr) {
        if (attr.value !== null) {
            return `${attr.key}:${attr.value}`;
        }
        return attr.key;
    }

    static _parseMedia(value) {
        const parts = value.split(' ');
        return {
            type: parts[0],
            port: parseInt(parts[1], 10),
            protocol: parts[2],
            fmt: parts.slice(3).join(' '),
            connection: null,
            attributes: []
        };
    }

    static _stringifyMedia(media) {
        return `${media.type} ${media.port} ${media.protocol} ${media.fmt}`;
    }

    static _parseConnection(value) {
        const parts = value.split(' ');
        return {
            netType: parts[0],
            addrType: parts[1],
            address: parts[2]
        };
    }

    static _stringifyConnection(conn) {
        return `${conn.netType} ${conn.addrType} ${conn.address}`;
    }

    static _parseEncryption(value) {
        const parts = value.split(' ');
        return {
            method: parts[0],
            key: parts.slice(1).join(' ') || null
        };
    }

    static _stringifyEncryption(encryption) {
        if (encryption.key) {
            return `${encryption.method} ${encryption.key}`;
        }
        return encryption.method;
    }

    static getIceUfrag(sdp) {
        const parsed = this.parse(sdp);
        const attr = parsed.attributes.find(a => a.key === 'ice-ufrag');
        return attr ? attr.value : null;
    }

    static getIcePwd(sdp) {
        const parsed = this.parse(sdp);
        const attr = parsed.attributes.find(a => a.key === 'ice-pwd');
        return attr ? attr.value : null;
    }

    static getMid(sdp) {
        const parsed = this.parse(sdp);
        for (const media of parsed.media) {
            const attr = media.attributes.find(a => a.key === 'mid');
            if (attr) return attr.value;
        }
        const globalAttr = parsed.attributes.find(a => a.key === 'mid');
        return globalAttr ? globalAttr.value : null;
    }

    static getSctpMap(sdp) {
        const parsed = this.parse(sdp);
        for (const media of parsed.media) {
            const attr = media.attributes.find(a => a.key === 'sctpmap');
            if (attr) {
                const parts = attr.value.split(' ');
                return {
                    sctpPort: parseInt(parts[0], 10),
                    protocol: parts[1],
                    maxMessageSize: parseInt(parts[2], 10)
                };
            }
        }
        return null;
    }

    static setIceUfrag(sdp, ufrag) {
        const parsed = this.parse(sdp);
        const idx = parsed.attributes.findIndex(a => a.key === 'ice-ufrag');
        if (idx >= 0) {
            parsed.attributes[idx].value = ufrag;
        } else {
            parsed.attributes.push({ key: 'ice-ufrag', value: ufrag });
        }
        return this.stringify(parsed);
    }

    static setIcePwd(sdp, pwd) {
        const parsed = this.parse(sdp);
        const idx = parsed.attributes.findIndex(a => a.key === 'ice-pwd');
        if (idx >= 0) {
            parsed.attributes[idx].value = pwd;
        } else {
            parsed.attributes.push({ key: 'ice-pwd', value: pwd });
        }
        return this.stringify(parsed);
    }

    static addIceCandidate(sdp, candidate) {
        const parsed = this.parse(sdp);
        parsed.attributes.push({ key: 'candidate', value: candidate });
        return this.stringify(parsed);
    }

    static generateOffer(options = {}) {
        const ufrag = options.ufrag || Math.random().toString(36).substring(2, 10);
        const pwd = options.pwd || Math.random().toString(36).substring(2, 24);
        const fingerprint = options.fingerprint || '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00';
        
        return this.stringify({
            version: 0,
            origin: {
                username: '-',
                sessionId: Date.now().toString(),
                sessionVersion: '2',
                netType: 'IN',
                addrType: 'IP4',
                unicastAddress: '127.0.0.1'
            },
            sessionName: '-',
            timing: { start: 0, stop: 0 },
            attributes: [
                { key: 'group', value: 'BUNDLE 0' },
                { key: 'msid-semantic', value: ' WMS' },
                { key: 'ice-ufrag', value: ufrag },
                { key: 'ice-pwd', value: pwd },
                { key: 'ice-options', value: 'trickle' },
                { key: 'fingerprint', value: `sha-256 ${fingerprint}` },
                { key: 'setup', value: 'actpass' }
            ],
            media: [{
                type: 'application',
                port: 9,
                protocol: 'UDP/DTLS/SCTP',
                fmt: 'webrtc-datachannel',
                attributes: [
                    { key: 'mid', value: '0' },
                    { key: 'sctp-port', value: '5000' },
                    { key: 'max-message-size', value: '262144' },
                    { key: 'setup', value: 'actpass' },
                    { key: 'fingerprint', value: `sha-256 ${fingerprint}` }
                ]
            }]
        });
    }

    static generateAnswer(options = {}) {
        const ufrag = options.ufrag || Math.random().toString(36).substring(2, 10);
        const pwd = options.pwd || Math.random().toString(36).substring(2, 24);
        const fingerprint = options.fingerprint || '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00';
        
        return this.stringify({
            version: 0,
            origin: {
                username: '-',
                sessionId: Date.now().toString(),
                sessionVersion: '2',
                netType: 'IN',
                addrType: 'IP4',
                unicastAddress: '127.0.0.1'
            },
            sessionName: '-',
            timing: { start: 0, stop: 0 },
            attributes: [
                { key: 'group', value: 'BUNDLE 0' },
                { key: 'msid-semantic', value: ' WMS' },
                { key: 'ice-ufrag', value: ufrag },
                { key: 'ice-pwd', value: pwd },
                { key: 'ice-options', value: 'trickle' },
                { key: 'fingerprint', value: `sha-256 ${fingerprint}` },
                { key: 'setup', value: 'active' }
            ],
            media: [{
                type: 'application',
                port: 9,
                protocol: 'UDP/DTLS/SCTP',
                fmt: 'webrtc-datachannel',
                attributes: [
                    { key: 'mid', value: '0' },
                    { key: 'sctp-port', value: '5000' },
                    { key: 'max-message-size', value: '262144' },
                    { key: 'setup', value: 'active' },
                    { key: 'fingerprint', value: `sha-256 ${fingerprint}` }
                ]
            }]
        });
    }
}

module.exports = SdpParser;