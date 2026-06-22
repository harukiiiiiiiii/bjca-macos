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
let messageId = 0;

// ---------------------------------------------------------------------------
// API call — sends JSON-RPC request to the local service
// ---------------------------------------------------------------------------

async function callAPI(method, params = {}) {
    const id = ++messageId;

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

console.log('[BJCA Bridge] Background service worker started');
