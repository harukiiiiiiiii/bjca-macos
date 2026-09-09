const assert = require('node:assert');
const fs = require('node:fs');
const vm = require('node:vm');

const bgSource = fs.readFileSync('extensions/chrome/background.js', 'utf8');
const injectSource = fs.readFileSync('extensions/chrome/inject.js', 'utf8');

// ---------------------------------------------------------------------------
// 1. Background tests
// ---------------------------------------------------------------------------
function setupBgContext({ fetchFn, abortTimeoutFn } = {}) {
  let messageListener = null;
  const chrome = {
    runtime: {
      onMessage: {
        addListener(fn) {
          messageListener = fn;
        }
      }
    }
  };

  const context = {
    chrome,
    console,
    fetch: fetchFn || (async () => ({ ok: true })),
    AbortSignal: {
      timeout: abortTimeoutFn || ((ms) => ({ timeoutMs: ms }))
    }
  };

  vm.runInNewContext(bgSource, context);
  return { context, messageListener };
}

async function sendBgMessage(listener, msg) {
  return new Promise((resolve) => {
    const keepOpen = listener(msg, {}, (response) => {
      resolve(response);
    });
    if (!keepOpen) {
      // Synchronous return (e.g. unknown message)
    }
  });
}

(async () => {
  // 1.1 Healthy response
  {
    let recordedSignal = null;
    let recordedUrl = null;
    let recordedOptions = null;
    const { messageListener } = setupBgContext({
      fetchFn: async (url, options) => {
        recordedUrl = url;
        recordedOptions = options;
        recordedSignal = options.signal;
        return { ok: true };
      },
      abortTimeoutFn: (ms) => ({ fakeSignalTimeout: ms })
    });

    const res = await sendBgMessage(messageListener, { type: 'checkHealth' });
    assert.strictEqual(res.ok, true);
    assert.strictEqual(recordedUrl, 'https://127.0.0.1:21061/health');
    assert.strictEqual(recordedOptions.cache, 'no-store');
    assert.deepStrictEqual(recordedSignal, { fakeSignalTimeout: 5000 });
  }

  // 1.2 Unhealthy response (HTTP 502 / ok: false)
  {
    const { messageListener } = setupBgContext({
      fetchFn: async () => ({ ok: false, status: 502 })
    });
    const res = await sendBgMessage(messageListener, { type: 'checkHealth' });
    assert.strictEqual(res.ok, false);
  }

  // 1.3 Thrown fetch (network / cert failure)
  {
    const { messageListener } = setupBgContext({
      fetchFn: async () => { throw new Error('NET::ERR_CERT_AUTHORITY_INVALID'); }
    });
    const res = await sendBgMessage(messageListener, { type: 'checkHealth' });
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.error, 'NET::ERR_CERT_AUTHORITY_INVALID');
  }

  // 1.4 Unknown message: rejected immediately without calling fetch
  {
    let fetchCalled = false;
    const { messageListener } = setupBgContext({
      fetchFn: async () => { fetchCalled = true; return { ok: true }; }
    });
    const res = await sendBgMessage(messageListener, { type: 'unknown_action', method: 'sign' });
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.error, 'unknown_message');
    assert.strictEqual(fetchCalled, false, 'fetch should not be called for unknown messages');
  }

  // ---------------------------------------------------------------------------
  // 2. Content script (inject.js) tests
  // ---------------------------------------------------------------------------
  function createDOM() {
    const elementsById = new Map();
    class MockElement {
      constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.attributes = {};
        this.style = {};
        this.listeners = {};
        this._id = '';
        this.textContent = '';
      }
      set id(val) {
        this._id = val;
        if (val) elementsById.set(val, this);
      }
      get id() { return this._id; }
      setAttribute(k, v) { this.attributes[k] = v; }
      getAttribute(k) { return this.attributes[k]; }
      append(...items) { this.children.push(...items); }
      appendChild(child) { this.children.push(child); return child; }
      addEventListener(evt, fn) { this.listeners[evt] = fn; }
      remove() {
        if (this._id) elementsById.delete(this._id);
        this.removed = true;
      }
    }

    const documentElement = new MockElement('html');
    const doc = {
      createElement(tag) { return new MockElement(tag); },
      getElementById(id) { return elementsById.get(id) || null; },
      documentElement
    };

    return { doc, elementsById };
  }

  // 2.1 Healthy: no warning prompt created
  {
    const { doc, elementsById } = createDOM();
    const window = {
      document: doc,
      WebSocket: function NativeWS() {},
      navigator: { plugins: [{ name: 'native-plugin' }] },
      ActiveXObject: undefined
    };
    window.top = window;

    const chrome = {
      runtime: {
        lastError: null,
        sendMessage(msg, cb) {
          if (msg.type === 'checkHealth') {
            cb({ ok: true });
          }
        }
      }
    };

    vm.runInNewContext(injectSource, {
      window,
      document: doc,
      chrome,
      console
    });

    assert.strictEqual(elementsById.has('bjca-health-warning'), false, 'Banner should not be created if healthy');
    assert.strictEqual(window.ActiveXObject, undefined, 'ActiveXObject should not be added/modified');
    assert.strictEqual(window.BJCAService, undefined, 'BJCAService should not be added');
    assert.strictEqual(window.WebSocket.name, 'NativeWS', 'WebSocket should remain unchanged');
    assert.strictEqual(window.navigator.plugins.length, 1, 'navigator.plugins should remain untouched');
  }

  // 2.2 Unhealthy: banner created with expected role, title, link, close button
  {
    const { doc, elementsById } = createDOM();
    const window = {
      document: doc,
      WebSocket: function NativeWS() {},
      navigator: { plugins: [{ name: 'native-plugin' }] },
      ActiveXObject: undefined
    };
    window.top = window;

    const chrome = {
      runtime: {
        lastError: null,
        sendMessage(msg, cb) {
          if (msg.type === 'checkHealth') {
            cb({ ok: false });
          }
        }
      }
    };

    vm.runInNewContext(injectSource, {
      window,
      document: doc,
      chrome,
      console
    });

    const banner = elementsById.get('bjca-health-warning');
    assert.ok(banner, 'Health warning banner should be displayed');
    assert.strictEqual(banner.getAttribute('role'), 'alert');
    assert.strictEqual(doc.documentElement.children.includes(banner), true);

    const [title, message, link, close] = banner.children;
    assert.strictEqual(title.textContent, 'BJCA 本地服务无法安全连接');
    assert.ok(message.textContent.includes('通常是本地证书尚未被 Chrome 信任'));
    assert.strictEqual(link.href, 'https://127.0.0.1:21061/health');
    assert.strictEqual(link.target, '_blank');
    assert.strictEqual(link.textContent, '打开本地检查页');
    assert.strictEqual(close.getAttribute('aria-label'), '关闭 BJCA 提示');

    // Close button dismisses banner
    close.listeners['click']();
    assert.strictEqual(elementsById.has('bjca-health-warning'), false);
    assert.strictEqual(banner.removed, true);
  }

  // 2.3 Extension context unavailable: runtime.lastError
  {
    const { doc, elementsById } = createDOM();
    const window = {
      document: doc,
      WebSocket: function NativeWS() {}
    };
    window.top = window;

    const chrome = {
      runtime: {
        lastError: { message: 'Extension context invalidated.' },
        sendMessage(msg, cb) {
          cb(null);
        }
      }
    };

    vm.runInNewContext(injectSource, { window, document: doc, chrome, console });
    const banner = elementsById.get('bjca-health-warning');
    assert.ok(banner, 'Health warning banner should be displayed on lastError');
    const [title, message, close] = banner.children;
    assert.strictEqual(title.textContent, 'BJCA 插件需要重新加载');
    assert.ok(message.textContent.includes('chrome://extensions'));
    assert.ok(message.textContent.includes('刷新交易页面'));
    assert.strictEqual(message.textContent.includes('继续访问'), false);
    assert.strictEqual(message.textContent.includes('证书'), false);
    assert.strictEqual(banner.children.some(c => c.tagName === 'A'), false, 'Should not contain check link');
  }

  // 2.4 Extension context unavailable: sync sendMessage throw
  {
    const { doc, elementsById } = createDOM();
    const window = {
      document: doc,
      WebSocket: function NativeWS() {}
    };
    window.top = window;

    const chrome = {
      runtime: {
        lastError: null,
        sendMessage() {
          throw new Error('Extension context invalidated.');
        }
      }
    };

    vm.runInNewContext(injectSource, { window, document: doc, chrome, console });
    const banner = elementsById.get('bjca-health-warning');
    assert.ok(banner, 'Health warning banner should be displayed on sync throw');
    const [title, message] = banner.children;
    assert.strictEqual(title.textContent, 'BJCA 插件需要重新加载');
    assert.ok(message.textContent.includes('chrome://extensions'));
    assert.ok(!message.textContent.includes('继续访问'));
  }

  // 2.5 Extension context unavailable: missing chrome.runtime in top frame
  {
    const { doc, elementsById } = createDOM();
    const window = {
      document: doc,
      WebSocket: function NativeWS() {}
    };
    window.top = window;

    vm.runInNewContext(injectSource, { window, document: doc, console });
    const banner = elementsById.get('bjca-health-warning');
    assert.ok(banner, 'Health warning banner should be displayed if runtime missing in top frame');
    const [title, message] = banner.children;
    assert.strictEqual(title.textContent, 'BJCA 插件需要重新加载');
    assert.ok(message.textContent.includes('chrome://extensions'));
  }

  // 2.6 Duplicate suppression (idempotent / already showing)
  {
    const { doc, elementsById } = createDOM();
    const window = {
      document: doc,
      WebSocket: function NativeWS() {}
    };
    window.top = window;

    let sendCount = 0;
    const chrome = {
      runtime: {
        lastError: null,
        sendMessage(msg, cb) {
          sendCount++;
          cb({ ok: false });
        }
      }
    };

    vm.runInNewContext(injectSource, { window, document: doc, chrome, console });
    // Run second time in same window
    vm.runInNewContext(injectSource, { window, document: doc, chrome, console });

    assert.strictEqual(sendCount, 1, 'Double injection in same window should be ignored');
    assert.strictEqual(doc.documentElement.children.length, 1);
  }

  // 2.7 Top-frame guard: iframe should not check health or display banner
  {
    const { doc, elementsById } = createDOM();
    const window = {
      document: doc,
      top: {} // Not equal to window
    };
    let sendCalled = false;
    const chrome = {
      runtime: {
        sendMessage() { sendCalled = true; }
      }
    };

    vm.runInNewContext(injectSource, { window, document: doc, chrome, console });
    assert.strictEqual(sendCalled, false, 'Subframe should not send checkHealth message');
    assert.strictEqual(elementsById.has('bjca-health-warning'), false);
  }

  console.log('chrome health prompt: ok');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
