const assert = require('node:assert');
const fs = require('node:fs');
const vm = require('node:vm');

const pageBridgeSource = fs.readFileSync('extensions/chrome/page-bridge.js', 'utf8');

function setupEnvironment() {
  const calls = [];
  class FakeWebSocket {
    constructor(url, protocols) {
      if (new.target === undefined) {
        throw new TypeError("Failed to construct 'WebSocket': Please use the 'new' operator");
      }
      this.url = url;
      this.protocols = protocols;
      calls.push({ url, protocols, instance: this });
    }
    customMethod() { return 'custom'; }
  }
  FakeWebSocket.CONNECTING = 0;
  FakeWebSocket.OPEN = 1;
  FakeWebSocket.CLOSING = 2;
  FakeWebSocket.CLOSED = 3;
  FakeWebSocket.prototype.customProto = 'proto-val';

  const window = {
    WebSocket: FakeWebSocket,
    URL: global.URL,
    location: { href: 'https://www.jspec.com.cn/' }
  };

  return { window, FakeWebSocket, calls };
}

// 1. Positive tests: known legacy targets redirect to TARGET_URL
{
  const { window, FakeWebSocket, calls } = setupEnvironment();
  vm.runInNewContext(pageBridgeSource, { window, console, URL: global.URL, Reflect, Proxy });

  // ws / wss 127.0.0.1:undefined (root, empty, /xtxapp, /xtxapp/)
  new window.WebSocket('ws://127.0.0.1:undefined', ['soap']);
  new window.WebSocket('wss://127.0.0.1:undefined/xtxapp', 'cryptokit-kdets-protocol');
  new window.WebSocket('ws://127.0.0.1:undefined/', ['soap']);
  new window.WebSocket('wss://127.0.0.1:undefined/xtxapp/');

  // ws / wss 127.0.0.1:21061
  new window.WebSocket('ws://127.0.0.1:21061');
  new window.WebSocket('wss://127.0.0.1:21061/');
  new window.WebSocket('ws://127.0.0.1:21061/xtxapp', ['soap']);
  new window.WebSocket('wss://127.0.0.1:21061/xtxapp/', ['cryptokit-kdets-protocol']);

  // URL object input
  new window.WebSocket(new URL('wss://127.0.0.1:21061/xtxapp'), ['soap']);
  new window.WebSocket(new URL('ws://127.0.0.1:21061/'));

  for (let i = 0; i < 10; i++) {
    assert.strictEqual(calls[i].url, 'wss://127.0.0.1:21061/xtxapp', `call ${i} url should be redirected`);
  }
  assert.deepStrictEqual(calls[0].protocols, ['soap']);
  assert.strictEqual(calls[1].protocols, 'cryptokit-kdets-protocol');
  assert.deepStrictEqual(calls[6].protocols, ['soap']);
  assert.deepStrictEqual(calls[7].protocols, ['cryptokit-kdets-protocol']);
  assert.deepStrictEqual(calls[8].protocols, ['soap']);
}

// 2. Negative tests: other local ports, other paths, remote query/lookalikes/credentials/fragments
{
  const { window, calls } = setupEnvironment();
  vm.runInNewContext(pageBridgeSource, { window, console, URL: global.URL, Reflect, Proxy });

  const negativeUrls = [
    'wss://example.com/socket',
    'ws://127.0.0.1:8080/xtxapp',
    'ws://127.0.0.1:80/xtxapp',
    'wss://127.0.0.1:21061/otherpath',
    'wss://127.0.0.1:21061/xtxapp?token=secret',
    'wss://127.0.0.1:21061/xtxapp#hash',
    'wss://user:pass@127.0.0.1:21061/xtxapp',
    'ws://127.0.0.1.attacker.com:21061/xtxapp',
    'ws://evil.com/?target=127.0.0.1:21061',
    'http://127.0.0.1:21061/xtxapp',
    'wss://127.0.0.1:undefined/otherpath',
    'wss://127.0.0.1:undefined?foo=bar',
    'wss://127.0.0.1:undefined#frag',
    'wss://user:pass@127.0.0.1:undefined/xtxapp',
    'wss://127.0.0.1:21061/xtxapp#',
    'wss://127.0.0.1:21061/xtxapp?',
    'wss://127.0.0.1:21061/other/../xtxapp',
    '  wss://127.0.0.1:21061/xtxapp  '
  ];

  for (const url of negativeUrls) {
    new window.WebSocket(url);
  }

  // Also negative URL object
  const negUrlObj = new URL('wss://127.0.0.1:8080/xtxapp');
  new window.WebSocket(negUrlObj);

  for (let i = 0; i < negativeUrls.length; i++) {
    assert.strictEqual(calls[i].url, negativeUrls[i], `negative test ${negativeUrls[i]} should not be modified`);
  }
  assert.strictEqual(calls[negativeUrls.length].url, negUrlObj, 'negative URL object should be passed untouched');

  // Custom object's toString counter test: bridge must not call toString before the constructor
  let customToStringCount = 0;
  const customObj = {
    toString() {
      customToStringCount++;
      return 'wss://127.0.0.1:21061/xtxapp';
    }
  };
  new window.WebSocket(customObj);
  assert.strictEqual(customToStringCount, 0, 'custom object toString must not be called in bridge before fake constructor');
  assert.strictEqual(calls[calls.length - 1].url, customObj, 'custom object passed untouched');
}

// 3. Static constants, prototype inheritance, and instanceof
{
  const { window, FakeWebSocket } = setupEnvironment();
  vm.runInNewContext(pageBridgeSource, { window, console, URL: global.URL, Reflect, Proxy });

  assert.strictEqual(window.WebSocket.CONNECTING, 0);
  assert.strictEqual(window.WebSocket.OPEN, 1);
  assert.strictEqual(window.WebSocket.CLOSING, 2);
  assert.strictEqual(window.WebSocket.CLOSED, 3);

  const ws = new window.WebSocket('wss://127.0.0.1:21061/xtxapp');
  assert.ok(ws instanceof FakeWebSocket, 'ws should be instanceof FakeWebSocket');
  assert.ok(ws instanceof window.WebSocket, 'ws should be instanceof window.WebSocket');
  assert.strictEqual(ws.customMethod(), 'custom');
  assert.strictEqual(ws.customProto, 'proto-val');

  // Subclassing
  class SubWebSocket extends window.WebSocket {}
  const subWs = new SubWebSocket('wss://127.0.0.1:21061/xtxapp');
  assert.ok(subWs instanceof SubWebSocket);
  assert.ok(subWs instanceof FakeWebSocket);

  // Calling without new throws TypeError
  assert.throws(() => {
    window.WebSocket('wss://127.0.0.1:21061/xtxapp');
  }, TypeError);
}

// 4. Idempotent injection
{
  const { window } = setupEnvironment();
  vm.runInNewContext(pageBridgeSource, { window, console, URL: global.URL, Reflect, Proxy });
  const firstWs = window.WebSocket;
  vm.runInNewContext(pageBridgeSource, { window, console, URL: global.URL, Reflect, Proxy });
  assert.strictEqual(window.WebSocket, firstWs, 'Second script execution should be a no-op');
}

console.log('chrome page bridge: ok');
