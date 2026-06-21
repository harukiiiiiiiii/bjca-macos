/**
 * BJCA Certificate Bridge — Background Service Worker
 *
 * Acts as the bridge between browser web pages and the local
 * bjca_service HTTPS + WebSocket server on 127.0.0.1:21061.
 *
 * Supports pages that reference the legacy XTXAppCOM control CLSID
 * {3F367B74-92D9-4C5E-AB93-234F8A91D5E6}.
 */

const SERVICE_URL = 'https://127.0.0.1:21061';
const API_URL = `${SERVICE_URL}/api`;
const WS_URL = 'wss://127.0.0.1:21061/xtxapp';

let wsConnection = null;
let messageId = 0;
let pendingRequests = new Map();

// ---------------------------------------------------------------------------
// WebSocket connection management
// ---------------------------------------------------------------------------

function connectWebSocket() {
    if (wsConnection && wsConnection.readyState === WebSocket.OPEN) {
        return;
    }

    wsConnection = new WebSocket(WS_URL);

    wsConnection.onopen = () => {
        console.log('[BJCA Bridge] WebSocket connected');
    };

    wsConnection.onmessage = (event) => {
        const response = JSON.parse(event.data);
        const id = response.id;

        if (pendingRequests.has(id)) {
            const { resolve } = pendingRequests.get(id);
            pendingRequests.delete(id);

            if (response.error) {
                resolve({ error: response.error });
            } else {
                resolve({ result: response.result });
            }
        }
    };

    wsConnection.onclose = () => {
        console.log('[BJCA Bridge] WebSocket disconnected, reconnecting...');
        wsConnection = null;
        setTimeout(connectWebSocket, 2000);
    };

    wsConnection.onerror = (err) => {
        console.error('[BJCA Bridge] WebSocket error:', err);
    };
}

// ---------------------------------------------------------------------------
// API call — sends JSON-RPC request to the local service
// ---------------------------------------------------------------------------

async function callAPI(method, params = {}) {
    const id = ++messageId;

    // Try WebSocket first
    if (wsConnection && wsConnection.readyState === WebSocket.OPEN) {
        return new Promise((resolve) => {
            pendingRequests.set(id, { resolve });
            wsConnection.send(JSON.stringify({
                jsonrpc: '2.0',
                method: method,
                params: params,
                id: id,
            }));

            // Timeout after 30s
            setTimeout(() => {
                if (pendingRequests.has(id)) {
                    pendingRequests.delete(id);
                    resolve({ error: { code: -32000, message: 'Timeout' } });
                }
            }, 30000);
        });
    }

    // Fallback to HTTP POST
    try {
        const response = await fetch(`${API_URL}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: method,
                params: params,
                id: id,
            }),
        });
        return await response.json();
    } catch (err) {
        return { error: { code: -32000, message: err.message } };
    }
}

// ---------------------------------------------------------------------------
// Handle requests from content scripts (injected into web pages)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    handleAPIRequest(request).then(sendResponse);
    return true;  // Keep message channel open for async response
});

async function handleAPIRequest(request) {
    const { method, params } = request;
    return await callAPI(method, params);
}

// ---------------------------------------------------------------------------
// Intercept requests to known ActiveX objects and redirect to our service
// ---------------------------------------------------------------------------

// The original Windows code creates COM objects like:
//   new ActiveXObject("XTXAppCOM.XTXSign.1")
//   CLSID: {3F367B74-92D9-4C5E-AB93-234F8A91D5E6}

// We inject a shim that replaces these with calls to our service.

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

connectWebSocket();
console.log('[BJCA Bridge] Background service worker started');
