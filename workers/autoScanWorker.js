const { parentPort } = require('worker_threads');
const si = require('systeminformation');
const SecurityService = require('../security/SecurityService');

let timer = null;
let signatures = { processNames: [], ports: [], domains: [] };

async function performScanOnce() {
	try {
		const securityService = new SecurityService();
		const [processes, currentLoad] = await Promise.all([
			si.processes().catch(() => ({ list: [] })),
			si.currentLoad().catch(() => ({ currentLoad: 0 }))
		]);
		
		const report = { 
			load: Number.isFinite(currentLoad.currentLoad) ? currentLoad.currentLoad : 0, 
			processes: (processes.list || []).slice(0, 500) 
		};
		
		const threats = await securityService.runAllChecks({
			processNames: signatures.processNames,
			ports: (signatures.ports || []).map(p => Number(p)),
			domains: signatures.domains
		});
		report.threats = threats;
		
		// Send threat detection results back to main process for event handling
		try { 
			parentPort.postMessage({ 
				type: 'result', 
				payload: { 
					ok: true, 
					report,
					hasThreats: threats && threats.length > 0,
					threatCount: threats ? threats.length : 0
				} 
			}); 
		} catch (e) {
			console.error('Failed to send scan result:', e.message);
		}
	} catch (e) {
		console.error('performScanOnce failed:', e.message);
		try { 
			parentPort.postMessage({ 
				type: 'result', 
				payload: { 
					ok: false, 
					error: String(e) 
				} 
			}); 
		} catch (sendError) {
			console.error('Failed to send error message:', sendError.message);
		}
	}
}

parentPort.on('message', (msg) => {
	if (!msg || !msg.type) return;
	if (msg.type === 'start') {
		signatures = msg.signatures || signatures;
		const interval = Number(msg.intervalMs) || 30000;
		if (timer) clearInterval(timer);
		timer = setInterval(() => { performScanOnce(); }, interval);
		performScanOnce();
	} else if (msg.type === 'stop') {
		if (timer) clearInterval(timer);
		timer = null;
	}
}); 