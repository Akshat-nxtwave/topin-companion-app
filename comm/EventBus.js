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
  // Allowed outbound events
  CLIENT_AND_APP_CONNECTED: 'CLIENT_AND_APP_CONNECTED',
  CLIENT_AND_APP_DISCONNECTED: 'CLIENT_AND_APP_DISCONNECTED',
  DETECTED_UNWANTED_APPS: 'DETECTED_UNWANTED_APPS',
  ACTIVE_NOTIFICATION_SERVICE: 'ACTIVE_NOTIFICATION_SERVICE',
  NO_ISSUES_DETECTED: 'NO_ISSUES_DETECTED',

  // Deprecated (kept for compatibility, but not forwarded)
  NOTIFICATION_AUDIT: 'NOTIFICATION_AUDIT',
  ERROR: 'ERROR'
});

// Set of events that are allowed to be sent to clients
const AllowedOutboundEvents = new Set([
  AppEvent.CLIENT_AND_APP_CONNECTED,
  AppEvent.CLIENT_AND_APP_DISCONNECTED,
  AppEvent.DETECTED_UNWANTED_APPS,
  AppEvent.ACTIVE_NOTIFICATION_SERVICE,
  AppEvent.NO_ISSUES_DETECTED
]);

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

module.exports = { EventBus, Stage, AppEvent, AllowedOutboundEvents };
















