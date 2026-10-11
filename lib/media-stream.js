class MediaStream {
    constructor(id) {
        this.id = id || Math.random().toString(36).substring(2, 15);
        this.tracks = new Map();
        this.active = true;
        this._listeners = {};
    }

    addTrack(track) {
        if (track) {
            this.tracks.set(track.id, track);
            this._emit('trackadded', { track });
        }
    }

    removeTrack(track) {
        if (track && this.tracks.has(track.id)) {
            this.tracks.delete(track.id);
            this._emit('trackremoved', { track });
        }
    }

    getTracks() {
        return Array.from(this.tracks.values());
    }

    getAudioTracks() {
        return this.getTracks().filter(track => track.kind === 'audio');
    }

    getVideoTracks() {
        return this.getTracks().filter(track => track.kind === 'video');
    }

    stop() {
        this.active = false;
        for (const track of this.tracks.values()) {
            track.stop();
        }
        this._emit('inactive');
    }

    clone() {
        const cloned = new MediaStream(this.id);
        for (const track of this.tracks.values()) {
            cloned.addTrack(track);
        }
        return cloned;
    }

    on(event, callback) {
        if (!this._listeners[event]) {
            this._listeners[event] = [];
        }
        this._listeners[event].push(callback);
    }

    off(event, callback) {
        if (this._listeners[event]) {
            this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
        }
    }

    _emit(event, data) {
        if (this._listeners[event]) {
            for (const callback of this._listeners[event]) {
                try {
                    callback(data);
                } catch (error) {
                    console.error('MediaStream event error:', error);
                }
            }
        }
    }
}

class MediaStreamTrack {
    constructor(kind, options = {}) {
        this.kind = kind;
        this.id = options.id || Math.random().toString(36).substring(2, 15);
        this.label = options.label || '';
        this.enabled = options.enabled !== false;
        this.muted = options.muted || false;
        this._ended = false;
        this._listeners = {};
    }

    stop() {
        this._ended = true;
        this.enabled = false;
        this._emit('ended');
    }

    clone() {
        return new MediaStreamTrack(this.kind, {
            id: this.id,
            label: this.label,
            enabled: this.enabled,
            muted: this.muted
        });
    }

    on(event, callback) {
        if (!this._listeners[event]) {
            this._listeners[event] = [];
        }
        this._listeners[event].push(callback);
    }

    off(event, callback) {
        if (this._listeners[event]) {
            this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
        }
    }

    _emit(event) {
        if (this._listeners[event]) {
            for (const callback of this._listeners[event]) {
                try {
                    callback();
                } catch (error) {
                    console.error('MediaStreamTrack event error:', error);
                }
            }
        }
    }
}

class MediaRecorder {
    constructor(stream, options = {}) {
        this.stream = stream;
        this.mimeType = options.mimeType || 'video/webm;codecs=vp8';
        this.bitsPerSecond = options.bitsPerSecond || 2500000;
        this.state = 'inactive';
        this._interval = null;
        this._data = [];
        this._listeners = {};
    }

    start(timeslice = 0) {
        if (this.state !== 'inactive') return;
        
        this.state = 'recording';
        this._data = [];
        this._emit('start');

        if (timeslice > 0) {
            this._interval = setInterval(() => {
                if (this.state === 'recording') {
                    this._emitDataAvailable();
                }
            }, timeslice);
        }
    }

    stop() {
        if (this.state !== 'recording') return;
        
        this.state = 'inactive';
        if (this._interval) {
            clearInterval(this._interval);
            this._interval = null;
        }
        
        this._emitDataAvailable();
        this._emit('stop');
    }

    pause() {
        if (this.state === 'recording') {
            this.state = 'paused';
            this._emit('pause');
        }
    }

    resume() {
        if (this.state === 'paused') {
            this.state = 'recording';
            this._emit('resume');
        }
    }

    _emitDataAvailable() {
        if (this._data.length > 0) {
            const blob = new Blob(this._data, { type: this.mimeType });
            this._emit('dataavailable', { data: blob });
            this._data = [];
        }
    }

    on(event, callback) {
        if (!this._listeners[event]) {
            this._listeners[event] = [];
        }
        this._listeners[event].push(callback);
    }

    off(event, callback) {
        if (this._listeners[event]) {
            this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
        }
    }

    _emit(event, data) {
        if (this._listeners[event]) {
            for (const callback of this._listeners[event]) {
                try {
                    callback(data);
                } catch (error) {
                    console.error('MediaRecorder event error:', error);
                }
            }
        }
    }
}

module.exports = {
    MediaStream,
    MediaStreamTrack,
    MediaRecorder
};