(function () {
  'use strict';

  if (window.__bjcaWebSocketBridgeInstalled) return;
  window.__bjcaWebSocketBridgeInstalled = true;

  const serviceUrl = 'wss://127.0.0.1:21061/xtxapp';
  const OriginalWebSocket = window.WebSocket;

  window.WebSocket = function (url, protocols) {
    if (typeof url === 'string' && url.includes('127.0.0.1')) {
      console.log('[BJCA Bridge] Redirecting WebSocket:', url, '->', serviceUrl);
      url = serviceUrl;
    }
    return new OriginalWebSocket(url, protocols);
  };
  window.WebSocket.prototype = OriginalWebSocket.prototype;
  window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
  window.WebSocket.OPEN = OriginalWebSocket.OPEN;
  window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
  window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
})();
