const http = require('http');
const { WebSocketServer } = require('ws');
const { AppEvent, AllowedOutboundEvents } = require('./EventBus');

class LocalServer {
  constructor(eventBus, options = {}) {
    this.eventBus = eventBus;
    this.port = Number(options.port) || 3035;
    this.host = options.host || '127.0.0.1';
    this.server = null;
    this.wss = null;
    this.unsubscribe = null;
  }

  start() {
    if (this.server) return this.port;
    this.server = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (req.method === 'POST' && req.url === '/emit') {
        let body = '';
        req.on('data', chunk => { body += chunk; if (body.length > 1024 * 1024) req.destroy(); });
        req.on('end', () => {
          try {
            const json = JSON.parse(body || '{}');
            const kind = json.kind === 'stage' ? 'stage' : 'event';
            if (kind === 'stage') this.eventBus.emitStage(json.name, json.payload || null);
            else this.eventBus.emitEvent(json.name, json.payload || null);
            res.writeHead(202, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ accepted: true }));
          } catch (e) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: String(e) }));
          }
        });
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    this.wss = new WebSocketServer({ noServer: true });
    const clients = new Set();

    this.server.on('upgrade', (req, socket, head) => {
      if (!req.url || !req.url.startsWith('/ws')) {
        socket.destroy();
        return;
      }
      this.wss.handleUpgrade(req, socket, head, (ws) => {
        this.wss.emit('connection', ws, req);
      });
    });

    this.wss.on('connection', (ws) => {
      clients.add(ws);
      try { this.eventBus.emitEvent(AppEvent.CLIENT_AND_APP_CONNECTED, { reason: 'ws_connection_established_Local' }); } catch {}
      ws.on('close', () => {
        clients.delete(ws);
        try { this.eventBus.emitEvent(AppEvent.CLIENT_AND_APP_DISCONNECTED, { reason: 'ws_connection_closed' }); } catch {}
      });
    });

    this.unsubscribe = this.eventBus.subscribe((message) => {
      // Only forward allowed outbound events; drop stages and unapproved events
      try {
        if (!message || message.kind !== 'event') return;
        if (!AllowedOutboundEvents || !AllowedOutboundEvents.has(String(message.name))) return;
        const json = JSON.stringify({ kind: 'event', name: message.name, payload: message.payload || null, ts: message.ts || Date.now() });
        for (const ws of clients) {
          try {
            if (ws.readyState === 1) ws.send(json);
          } catch {}
        }
      } catch {}
    });

    this.server.listen(this.port, this.host);
    return this.port;
  }

  stop() {
    try { if (this.unsubscribe) this.unsubscribe(); } catch {}
    this.unsubscribe = null;
    try { if (this.wss) this.wss.clients.forEach(ws => { try { ws.close(); } catch {} }); } catch {}
    try { this.wss && this.wss.close(); } catch {}
    this.wss = null;
    try { this.server && this.server.close(); } catch {}
    this.server = null;
    return true;
  }
}

module.exports = { LocalServer };
















