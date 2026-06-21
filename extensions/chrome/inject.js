/**
 * BJCA Certificate Bridge — Content Script Injection
 *
 * This script is injected into web pages to provide JavaScript proxies
 * that call the local macOS service through the Chrome extension API.
 *
 * Browser pages may request these legacy control identifiers:
 *   ActiveXObject("XTXAppCOM.XTXSign.1")
 *   ActiveXObject("XTXSecX.XTXSecXCtrl.1")
 *   CLSID: {3F367B74-92D9-4C5E-AB93-234F8A91D5E6}
 */

(function() {
    'use strict';

    // Prevent double-injection
    if (window.__bjcaBridgeInjected) return;
    window.__bjcaBridgeInjected = true;

    // -----------------------------------------------------------------------
    // WebSocket interception — redirect ALL localhost WS/WSS to our service
    // -----------------------------------------------------------------------
    const BJCA_WS_URL = 'wss://127.0.0.1:21061/xtxapp';
    const OriginalWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        if (typeof url === 'string' && url.includes('127.0.0.1')) {
            console.log('[BJCA Bridge] Redirecting WebSocket:', url, '→', BJCA_WS_URL);
            url = BJCA_WS_URL;
        }
        return new OriginalWebSocket(url, protocols);
    };
    window.WebSocket.prototype = OriginalWebSocket.prototype;
    window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    window.WebSocket.OPEN = OriginalWebSocket.OPEN;
    window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
    window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;

    console.log('[BJCA Bridge] Injected into page:', window.location.href);

    // -----------------------------------------------------------------------
    // API proxy — sends requests from the page to our local service
    // -----------------------------------------------------------------------

    function sendToService(method, params) {
        return new Promise((resolve, reject) => {
            try {
                chrome.runtime.sendMessage(
                    { method: method, params: params },
                    (response) => {
                        if (chrome.runtime.lastError) {
                            reject(new Error(chrome.runtime.lastError.message));
                        } else if (response && response.error) {
                            reject(new Error(response.error.message));
                        } else if (response && response.result) {
                            resolve(response.result);
                        } else {
                            reject(new Error('Unknown error'));
                        }
                    }
                );
            } catch (err) {
                reject(err);
            }
        });
    }

    // -----------------------------------------------------------------------
    // Shims for the original XTX COM objects
    // -----------------------------------------------------------------------

    /**
     * Shim for XTXAppCOM.XTXSign (the main signing COM object).
     *
     * Supported certificate-control methods:
     *   GetDeviceCount, GetAllDeviceSN, InitDevice,
     *   ImportSignCert, ImportEncCert,
     *   AnySign_SignData, AnySign_SignPkcs7Data, AnySign_SignHashData,
     *   ExportPKCS10, ExportPubKey, GenerateKeyPair, etc.
     */
    class XTXAppCOM {
        constructor() {
            this._initialized = false;
            this._deviceIndex = 0;
        }

        async GetDeviceCount() {
            const r = await sendToService('list_devices', {});
            return r.count;
        }

        async GetAllDeviceSN() {
            const r = await sendToService('list_devices', {});
            return (r.devices || []).map(d => d.device_sn || '');
        }

        async GetDeviceInfo(index) {
            return await sendToService('get_device_info', { index: index });
        }

        async InitDevice(index, pin) {
            const r = await sendToService('init_device', {
                index: index,
                pin: pin,
            });
            this._initialized = r.initialized;
            this._deviceIndex = index;
            return r.initialized;
        }

        async GetContainerCount() {
            const r = await sendToService('get_container_count', {});
            return r.count;
        }

        async ListCertificates() {
            return await sendToService('list_certificates', {});
        }

        async ImportSignCert(certB64) {
            return await sendToService('import_certificate', {
                cert_data: certB64,
                cert_type: 'sign',
            });
        }

        async ImportEncCert(certB64) {
            return await sendToService('import_certificate', {
                cert_data: certB64,
                cert_type: 'enc',
            });
        }

        async ImportPfx(pfxB64, password) {
            return await sendToService('import_pfx', {
                pfx_data: pfxB64,
                password: password,
            });
        }

        async SignData(dataB64, algorithm) {
            const r = await sendToService('sign', {
                data: dataB64,
                algorithm: algorithm || 'SM3withSM2',
            });
            return r.signature;
        }

        async SignPkcs7Data(dataB64) {
            const r = await sendToService('sign_pkcs7', {
                data: dataB64,
            });
            return r.pkcs7;
        }

        async SignHashData(hashB64, algorithm) {
            const r = await sendToService('sign_hash', {
                hash: hashB64,
                algorithm: algorithm || 'SM3withSM2',
            });
            return r.signature;
        }

        async ExportPKCS10(subjectCN) {
            return await sendToService('generate_csr', {
                subject_cn: subjectCN || 'BJCA User',
            });
        }

        async GetPicture(sealId) {
            return await sendToService('get_seal_image', {
                seal_id: sealId || '',
            });
        }

        async EnumESeal() {
            return await sendToService('list_seals', {});
        }

        async ChangeAdminPass(oldPin, newPin) {
            return await sendToService('change_pin', {
                old_pin: oldPin,
                new_pin: newPin,
            });
        }

        async GetCertificate(certId) {
            return await sendToService('get_certificate', {
                cert_id: certId || '',
            });
        }

        async ParseCertificate(certB64) {
            return await sendToService('parse_certificate', {
                cert_data: certB64,
            });
        }

        async ValidateCertificate(certB64) {
            return await sendToService('validate_certificate', {
                cert_data: certB64,
            });
        }
    }

    /**
     * Shim for XTXSecX.XTXSecXCtrl (hash/signature helper).
     */
    class XTXSecX {
        async Hash(dataB64, algorithm) {
            const r = await sendToService('hash', {
                data: dataB64,
                algorithm: algorithm || 'SHA256',
            });
            return r.hash;
        }

        async Verify(dataB64, signatureB64, certB64) {
            return await sendToService('verify', {
                data: dataB64,
                signature: signatureB64,
                cert_data: certB64,
            });
        }

        async VerifyPKCS7(pkcs7B64) {
            return await sendToService('verify_pkcs7', {
                pkcs7: pkcs7B64,
            });
        }
    }

    /**
     * Shim for the health/service status check.
     */
    class CertEnvService {
        async Health() {
            const r = await fetch('https://127.0.0.1:21061/health');
            return await r.json();
        }

        async GetVersion() {
            const h = await this.Health();
            return h.version;
        }
    }

    // -----------------------------------------------------------------------
    // Replace ActiveXObject
    // -----------------------------------------------------------------------

    const OriginalActiveXObject = window.ActiveXObject;

    window.ActiveXObject = function(progID) {
        console.log('[BJCA Bridge] ActiveXObject intercepted:', progID);

        // XTXAppCOM (main COM component)
        if (progID && (
            progID.toUpperCase().includes('XTXAPPCOM') ||
            progID.includes('3F367B74-92D9-4C5E-AB93-234F8A91D5E6')
        )) {
            console.log('[BJCA Bridge] Creating XTXAppCOM shim');
            return new XTXAppCOM();
        }

        // XTXSecX (signature helper)
        if (progID && progID.toUpperCase().includes('XTXSECX')) {
            console.log('[BJCA Bridge] Creating XTXSecX shim');
            return new XTXSecX();
        }

        // XTXSecXV2
        if (progID && progID.toUpperCase().includes('XTXSECXV2')) {
            console.log('[BJCA Bridge] Creating XTXSecX shim');
            return new XTXSecX();
        }

        // Fallback to original ActiveXObject (won't work on non-Windows)
        if (OriginalActiveXObject) {
            return new OriginalActiveXObject(progID);
        }

        // Unknown object — return a basic shim
        console.warn('[BJCA Bridge] Unknown ActiveX:', progID);
        return {};
    };

    // -----------------------------------------------------------------------
    // Replace navigator.plugins detection (some sites check for the plugin)
    // -----------------------------------------------------------------------

    if (navigator.plugins) {
        // Add a fake plugin for sites that check for npxtxhost
        Object.defineProperty(navigator, 'plugins', {
            get: function() {
                // Return original plugins array extended with our shim
                return navigator.plugins;
            },
            configurable: true,
        });
    }

    // -----------------------------------------------------------------------
    // Expose the service for direct JavaScript access
    // -----------------------------------------------------------------------

    window.BJCAService = {
        XTXAppCOM: XTXAppCOM,
        XTXSecX: XTXSecX,
        CertEnvService: CertEnvService,
        call: sendToService,
    };

    console.log('[BJCA Bridge] Shim initialized. Available APIs:');
    console.log('  window.BJCAService.XTXAppCOM');
    console.log('  window.BJCAService.XTXSecX');
    console.log('  window.BJCAService.call(method, params)');
})();
