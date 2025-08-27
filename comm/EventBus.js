const { EventEmitter } = require('events');

const Stage = Object.freeze({
  INIT: 'INIT',
  READY: 'READY',
  SCAN_STARTED: 'SCAN_STARTED',
  SCAN_COMPLETED: 'SCAN_COMPLETED',
  AUTO_SCAN_STARTED: 'AUTO_SCAN_STARTED',
  AUTO_SCAN_RESULT: 'AUTO_SCAN_RESULT',
  AUTO_SCAN_STOPPED: 'AUTO_SCAN_STOPPED'
});

const AppEvent = Object.freeze({
  NOTIFICATION_AUDIT: 'NOTIFICATION_AUDIT',
  ERROR: 'ERROR'
});

class EventBus extends EventEmitter {
  emitStage(stage, payload = null) {
    const message = {
      kind: 'stage',
      name: String(stage),
      payload,
      ts: Date.now()
    };
    this.emit('message', message);
  }

  emitEvent(eventName, payload = null) {
    const message = {
      kind: 'event',
      name: String(eventName),
      payload,
      ts: Date.now()
    };
    this.emit('message', message);
  }

  subscribe(listener) {
    this.on('message', listener);
    return () => this.off('message', listener);
  }
}

module.exports = { EventBus, Stage, AppEvent };















