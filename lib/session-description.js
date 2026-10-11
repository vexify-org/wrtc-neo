class RTCSessionDescription {
    constructor(init) {
        if (!init || typeof init !== 'object') {
            throw new TypeError('RTCSessionDescription constructor requires an object');
        }
        if (!init.type || typeof init.type !== 'string') {
            throw new TypeError('RTCSessionDescription type must be a string');
        }
        this.type = init.type;
        this.sdp = init.sdp || '';
    }

    toJSON() {
        return {
            type: this.type,
            sdp: this.sdp
        };
    }
}

module.exports = RTCSessionDescription;