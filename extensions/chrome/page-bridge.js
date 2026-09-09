(function () {
  'use strict';

  if (window.__bjcaWebSocketBridgeInstalled) return;
  window.__bjcaWebSocketBridgeInstalled = true;

  const TARGET_URL = 'wss://127.0.0.1:21061/xtxapp';
  const REDIRECT_REGEX = /^wss?:\/\/127\.0\.0\.1:(?:undefined|21061)(?:\/(?:xtxapp\/?)?)?$/i;
  const OriginalWebSocket = window.WebSocket;
  if (!OriginalWebSocket) return;

  function shouldRedirect(urlInput) {
    if (typeof urlInput === 'string') {
      return REDIRECT_REGEX.test(urlInput);
    }
    if (urlInput instanceof URL) {
      return REDIRECT_REGEX.test(urlInput.href);
    }
    return false;
  }

  const WebSocketProxy = new Proxy(OriginalWebSocket, {
    construct(target, args, newTarget) {
      let finalArgs = args;
      if (args.length > 0 && shouldRedirect(args[0])) {
        finalArgs = [TARGET_URL, ...args.slice(1)];
      }
      return Reflect.construct(target, finalArgs, newTarget);
    }
  });

  window.WebSocket = WebSocketProxy;
})();
