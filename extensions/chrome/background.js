/**
 * BJCA Certificate Bridge — Background Service Worker
 *
 * Checks BJCA local service health on 127.0.0.1:21061 for content scripts.
 */

const HEALTH_URL = 'https://127.0.0.1:21061/health';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!request || request.type !== 'checkHealth') {
    sendResponse({ ok: false, error: 'unknown_message' });
    return false;
  }

  handleCheckHealth().then(sendResponse);
  return true;
});

async function handleCheckHealth() {
  try {
    const fetchOptions = { cache: 'no-store' };
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
      fetchOptions.signal = AbortSignal.timeout(5000);
    }
    const response = await fetch(HEALTH_URL, fetchOptions);
    return { ok: Boolean(response && response.ok) };
  } catch (err) {
    return { ok: false, error: err && err.message ? err.message : 'health_check_failed' };
  }
}

console.log('[BJCA Bridge] Background service worker started');
