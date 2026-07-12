const assert = require('node:assert');
const fs = require('node:fs');
const vm = require('node:vm');

const calls = [];
function FakeWebSocket(url, protocols) {
  calls.push({ url, protocols });
}
FakeWebSocket.prototype = {};
Object.assign(FakeWebSocket, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });

const window = { WebSocket: FakeWebSocket, location: { href: 'https://www.jspec.com.cn/' } };
vm.runInNewContext(
  fs.readFileSync('extensions/chrome/page-bridge.js', 'utf8'),
  { window, console },
);

new window.WebSocket('wss://127.0.0.1:undefined', ['soap']);
new window.WebSocket('wss://example.com/socket');

assert.deepStrictEqual(calls[0], {
  url: 'wss://127.0.0.1:21061/xtxapp',
  protocols: ['soap'],
});
assert.strictEqual(calls[1].url, 'wss://example.com/socket');
assert.strictEqual(window.WebSocket.OPEN, 1);
console.log('chrome page bridge: ok');
