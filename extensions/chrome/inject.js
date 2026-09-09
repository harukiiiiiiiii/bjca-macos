/**
 * BJCA Certificate Bridge — Content Script (Isolated World)
 *
 * Checks BJCA local service health from top-level frames and displays
 * a warning prompt if the local service is unreachable or untrusted.
 */

(function () {
  'use strict';

  if (window.__bjcaHealthPromptInstalled) return;
  window.__bjcaHealthPromptInstalled = true;

  function showHealthWarning(isExtensionUnavailable) {
    if (document.getElementById('bjca-health-warning')) return;

    const banner = document.createElement('div');
    banner.id = 'bjca-health-warning';
    banner.setAttribute('role', 'alert');
    banner.style.cssText = [
      'position:fixed',
      'top:16px',
      'right:16px',
      'z-index:2147483647',
      'max-width:420px',
      'padding:16px 44px 16px 18px',
      'border:1px solid #f5c26b',
      'border-radius:10px',
      'background:#fff8e8',
      'color:#3d2b0b',
      'box-shadow:0 8px 28px rgba(0,0,0,.18)',
      'font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
    ].join(';');

    const title = document.createElement('strong');
    title.style.display = 'block';
    title.style.marginBottom = '4px';

    const message = document.createElement('div');

    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = '×';
    close.setAttribute('aria-label', '关闭 BJCA 提示');
    close.style.cssText = 'position:absolute;top:8px;right:10px;border:0;background:transparent;color:#6b5528;font-size:24px;cursor:pointer';
    close.addEventListener('click', () => banner.remove());

    if (isExtensionUnavailable) {
      title.textContent = 'BJCA 插件需要重新加载';
      message.textContent = '浏览器扩展上下文已失效或未响应。请在 chrome://extensions 中重新加载 BJCA 插件，然后刷新交易页面。';
      banner.append(title, message, close);
    } else {
      title.textContent = 'BJCA 本地服务无法安全连接';
      message.textContent = '通常是本地证书尚未被 Chrome 信任，也可能是服务未启动。请打开检查页，在警告页点击“高级”→“继续访问 127.0.0.1（不安全）”，看到 status: ok 后返回并刷新交易中心。';

      const link = document.createElement('a');
      link.href = 'https://127.0.0.1:21061/health';
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = '打开本地检查页';
      link.style.cssText = 'display:inline-block;margin-top:10px;color:#075fc7;font-weight:600;text-decoration:underline';

      banner.append(title, message, link, close);
    }

    document.documentElement.appendChild(banner);
  }

  if (window.top === window) {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
      showHealthWarning(true);
    } else {
      try {
        chrome.runtime.sendMessage({ type: 'checkHealth' }, (response) => {
          if (chrome.runtime.lastError) {
            showHealthWarning(true);
          } else if (!response || !response.ok) {
            showHealthWarning(false);
          }
        });
      } catch (_) {
        showHealthWarning(true);
      }
    }
  }
})();
