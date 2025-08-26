const { WebSocket } = require('ws');

class RemoteClient {
  constructor(eventBus, options = {}) {
    this.eventBus = eventBus;
    this.endpoint = options.endpoint || null; // full ws(s):// URL will be provided later
    this.token = options.token || null;
    this.ws = null;
    this.unsubscribe = null;
    this.reconnectDelayMs = 3000;
    this._stopped = false;
  }

  configure({ endpoint, token }) {
    if (endpoint) this.endpoint = endpoint;
    if (typeof token !== 'undefined') this.token = token;
  }

  start() {
    if (!this.endpoint) return false;
    this._stopped = false;
    this._connect();
    if (!this.unsubscribe) {
      this.unsubscribe = this.eventBus.subscribe((message) => {
        this._send(message);
      });
    }
    return true;
  }

  stop() {
    this._stopped = true;
    try { if (this.unsubscribe) this.unsubscribe(); } catch {}
    this.unsubscribe = null;
    try { if (this.ws) this.ws.close(); } catch {}
    this.ws = null;
    return true;
  }

  _connect() {
    if (this._stopped || !this.endpoint) return;
    try {
      const headers = this.token ? { Authorization: `Bearer ${this.token}` } : undefined;
      this.ws = new WebSocket(this.endpoint, { headers });
    } catch (e) {
      setTimeout(() => this._connect(), this.reconnectDelayMs);
      return;
    }

    this.ws.on('open', () => {
      // no-op; server may require an initial handshake; app can add later
    });

    this.ws.on('close', () => {
      this.ws = null;
      if (!this._stopped) setTimeout(() => this._connect(), this.reconnectDelayMs);
    });

    this.ws.on('error', () => {
      try { this.ws && this.ws.close(); } catch {}
    });
  }

  _send(message) {
    try {
      if (this.ws && this.ws.readyState === 1) {
        this.ws.send(JSON.stringify(message));
      }
    } catch {}
  }
}

module.exports = { RemoteClient };













