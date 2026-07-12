"""
Main HTTP + WebSocket server.

Implements the localhost-only JSON-RPC service expected by browser clients:
  - HTTP REST: GET /health, GET /A/certs, GET /A/cert.pem, POST /api/<method>
  - WebSocket: wss://127.0.0.1:21061/xtxapp

Security: ONLY listens on 127.0.0.1 (localhost) by default.
"""

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

_VENDOR_PATH = Path(__file__).resolve().parents[1] / "vendor"
if _VENDOR_PATH.exists():
    sys.path.insert(0, str(_VENDOR_PATH))

from aiohttp import web, WSMsgType
import aiohttp_cors
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .api_handlers import APIHandler, get_handler, APIError
from .config import ServiceConfig, get_config, set_config
from .notifications import notify

logger = logging.getLogger(__name__)


ALLOWED_ORIGIN_HOSTS = {
    "jspec.com.cn",
    "www.jspec.com.cn",
}
ALLOWED_ORIGIN_SUFFIXES = (
    ".sgcc.com.cn",
)
WEBSOCKET_PROTOCOLS = ("cryptokit-kdets-protocol",)


def _origin_allowed(origin: str) -> bool:
    if not origin:
        return False
    parsed = urlparse(origin)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and (
        host in ALLOWED_ORIGIN_HOSTS
        or any(host.endswith(suffix) for suffix in ALLOWED_ORIGIN_SUFFIXES)
    )


def _log_ws(label: str, method: str, call_cmd_id: str = "", ok: Optional[bool] = None) -> None:
    parts = [label, f"method={method or '-'}"]
    if call_cmd_id:
        parts.append(f"call_id={call_cmd_id}")
    if ok is not None:
        parts.append(f"ok={str(ok).lower()}")
    logger.info(" ".join(parts))


def _response_ok(response: dict) -> bool:
    if "error" in response:
        return False
    return bool(response.get("retVal", response.get("retValue", True)))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(config: ServiceConfig) -> None:
    """Configure logging to both console and file."""
    log_format = (
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"
    )
    level = getattr(logging, config.log_level.upper(), logging.DEBUG)

    if not config.log_path:
        config.log_path = os.path.join(os.path.expanduser("~"), ".bjca", "log")
    try:
        os.makedirs(config.log_path, exist_ok=True)
    except PermissionError:
        config.log_path = os.path.join(os.path.expanduser("~"), ".bjca", "log")
        os.makedirs(config.log_path, exist_ok=True)

    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(
                os.path.join(config.log_path, "bjca_service.log")
            ),
        ],
    )

    # Quiet noisy libraries
    for lib in ["aiohttp", "asyncio"]:
        logging.getLogger(lib).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# HTTP Request Handlers
# ---------------------------------------------------------------------------

class ServerHandlers:
    """HTTP route handlers for the aiohttp web server."""

    def __init__(self, api_handler: APIHandler):
        self._api = api_handler

    # ---- Health Check (mirrors mod_health.c → GET /health) ----

    async def health(self, request: web.Request) -> web.Response:
        result = await self._api.health()
        return web.json_response(result)

    # ---- /A/certs (certificate list, mirrors the Apache Location /A/certs) ----

    async def list_certs(self, request: web.Request) -> web.Response:
        result = await self._api.list_certificates()
        return web.json_response(result)

    # ---- /A/cert.pem (certificate export) ----

    async def cert_pem(self, request: web.Request) -> web.Response:
        cert_id = request.query.get("id", "")
        result = await self._api.get_certificate({"cert_id": cert_id})

        if "certificate" in result and "pem" in result["certificate"]:
            return web.Response(
                text=result["certificate"]["pem"],
                content_type="application/x-pem-file",
            )
        return web.json_response(result, status=404)

    # ---- JSON-RPC API (mirrors mod_ajax.c → POST /api) ----

    async def api(self, request: web.Request) -> web.Response:
        """
        Handle JSON-RPC API calls.

        Accepts:
          POST /api            → Dispatch to method in request body
          POST /api/<method>   → Use URL path as method name
        """
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"jsonrpc": "2.0", "error": {
                    "code": -32700, "message": "Parse error"
                }, "id": 0},
                status=400,
            )

        # URL path can override the method
        path_method = request.match_info.get("method", "")
        if path_method:
            body["method"] = path_method

        result = await self._api.handle_request(body)
        return web.json_response(result)

    # ---- Static File Serving (config data, PKI certs) ----

    async def static_file(self, request: web.Request) -> web.Response:
        """Serve static configuration/data files."""
        filename = request.match_info.get("filename", "index.html")
        config = get_config()

        # Search in data directories
        search_paths = [
            Path(config.cert_data_path) / filename,
            Path(config.bjca_root) / "data" / filename,
            Path("./config") / filename,
        ]

        for path in search_paths:
            if path.exists():
                return web.FileResponse(path)

        return web.Response(text="Not found", status=404)


# ---------------------------------------------------------------------------
# WebSocket Handler (mirrors mod_websocket.c)
# ---------------------------------------------------------------------------

class WebSocketManager:
    """
    WebSocket connection manager — replaces mod_websocket.c in XTXCoreSvr.

    Handles bidirectional JSON messaging with browser-based clients.
    """

    def __init__(self, api_handler: APIHandler):
        self._api = api_handler
        self._connections: set[web.WebSocketResponse] = set()

    async def handle_connection(self, request: web.Request) -> web.WebSocketResponse:
        """
        Handle a WebSocket connection.

        This mirrors the websocket-handler in Apache's mod_websocket.c.
        Each message is a JSON-RPC request; each response is sent back.
        """
        # Verify localhost (mirrors the [mod_ajax] IP check)
        peer = request.transport.get_extra_info("peername")
        if peer and peer[0] != "127.0.0.1":
            logger.warning(f"Rejected non-localhost WebSocket from {peer[0]}")
            raise web.HTTPForbidden(text="Localhost only")
        origin = request.headers.get("Origin", "")
        if not _origin_allowed(origin):
            logger.warning("Rejected WebSocket origin: %s", origin or "<missing>")
            raise web.HTTPForbidden(text="Forbidden origin")

        ws = web.WebSocketResponse(protocols=WEBSOCKET_PROTOCOLS)
        await ws.prepare(request)

        self._connections.add(ws)
        logger.info(
            f"WebSocket connected from {peer[0]}:{peer[1]}"
            if peer else "WebSocket connected"
        )

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        request_data = json.loads(msg.data)
                        call_cmd_id = request_data.get("call_cmd_id", "")

                        # Bridge website protocol → JSON-RPC.
                        method = request_data.get("xtx_func_name") or request_data.get("func") or request_data.get("method") or ""
                        _log_ws("WS RECV", method, call_cmd_id)
                        if method:
                            request_data["method"] = method
                        request_data["params"] = request_data.get("param", request_data.get("params", {}))
                        request_data["id"] = request_data.get("call_cmd_id", 1)

                        jrpc_response = await self._api.handle_request(request_data)

                        # Rewrite to BJCA wire format.
                        # The browser protocol embeds result fields at the top
                        # level (no "result" wrapper), with only call_cmd_id added.
                        wire_response: dict = {"call_cmd_id": call_cmd_id}
                        if "error" in jrpc_response:
                            wire_response["error"] = jrpc_response["error"]
                        else:
                            inner = jrpc_response.get("result", {})
                            wire_response.update(inner)
                        _log_ws("WS SEND", method, call_cmd_id, _response_ok(wire_response))
                        await ws.send_json(wire_response)
                    except json.JSONDecodeError:
                        logger.warning("WS non-JSON: %s", msg.data[:200])
                    except json.JSONDecodeError:
                        await ws.send_json({
                            "jsonrpc": "2.0",
                            "error": {"code": -32700, "message": "Parse error"},
                            "id": 0,
                        })
                    except Exception as e:
                        logger.exception("WebSocket handler error")
                        await ws.send_json({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32603,
                                "message": str(e),
                            },
                            "id": 0,
                        })

                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")

        except asyncio.CancelledError:
            pass
        finally:
            self._connections.discard(ws)
            logger.info("WebSocket disconnected")

        return ws

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected WebSocket clients."""
        dead = set()
        for ws in self._connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        self._connections -= dead


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

def create_app(config: ServiceConfig = None) -> web.Application:
    """
    Create and configure the aiohttp application.

    Route structure:
      GET  /health           → Health check
      GET  /A/certs          → Certificate list (JSON)
      GET  /A/cert.pem       → Certificate export (PEM)
      GET  /data/{filename}  → Static configuration files
      POST /api              → JSON-RPC dispatcher
      POST /api/{method}     → Named JSON-RPC call
      WS   /xtxapp           → WebSocket (bidirectional JSON-RPC)
    """
    if config is None:
        config = get_config()
    set_config(config)

    handler = get_handler()
    http_handlers = ServerHandlers(handler)
    ws_manager = WebSocketManager(handler)

    app = web.Application()

    # CORS setup — allow local browser access
    cors = aiohttp_cors.setup(app, defaults={
        "https://jspec.com.cn": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        ),
        "https://www.jspec.com.cn": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        )
    })

    # --- Routes ---

    # Health
    app.router.add_get("/health", http_handlers.health)

    # Certificate endpoints (mirrors Apache <Location /A/...>)
    app.router.add_get("/A/certs", http_handlers.list_certs)
    app.router.add_get("/A/cert.pem", http_handlers.cert_pem)

    # JSON-RPC API
    app.router.add_post("/api", http_handlers.api)
    app.router.add_post("/api/{method}", http_handlers.api)

    # WebSocket
    app.router.add_get("/xtxapp", ws_manager.handle_connection)
    app.router.add_get("/xtxapp/", ws_manager.handle_connection)

    # Static data files
    app.router.add_get("/data/{filename}", http_handlers.static_file)

    # Apply CORS to all routes
    for route in list(app.router.routes()):
        cors.add(route)

    # Store managers on app for cleanup
    app["ws_manager"] = ws_manager
    app["api_handler"] = handler

    async def startup(app):
        app["device_monitor_task"] = asyncio.create_task(
            _monitor_device_presence(handler)
        )

    async def cleanup(app):
        task = app.get("device_monitor_task")
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app.on_startup.append(startup)
    app.on_cleanup.append(cleanup)

    logger.info("Application created with routes:")
    for route in app.router.routes():
        logger.info(f"  {route.method} {route.resource}")

    return app


async def _monitor_device_presence(api_handler: APIHandler) -> None:
    """Notify when a USB Key is inserted or removed while the service runs."""
    previous_present, _ = _read_device_presence(api_handler)
    logger.info(
        "USB Key monitor initial state: %s",
        "present" if previous_present else "not present",
    )

    while True:
        await asyncio.sleep(2)
        try:
            present, name = _read_device_presence(api_handler)
            if present and not previous_present:
                logger.info("USB Key inserted: %s", name)
                notify("UKey 已插入", f"{name} 已插入")
            elif not present and previous_present:
                logger.info("USB Key removed")
                notify("UKey 已拔出", "UKey 已拔出")
            previous_present = present
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("device monitor check failed: %s", e)


def _read_device_presence(api_handler: APIHandler) -> tuple[bool, str]:
    """Read UKey presence without opening/probing the token."""
    try:
        info = api_handler._dev.get_presence_info()
        return bool(info.get("present")), info.get("name") or "UKey"
    except Exception as e:
        logger.debug("device presence snapshot failed: %s", e)
        return False, "UKey"


def _device_display_name(device: dict) -> str:
    return (
        device.get("token_label")
        or device.get("product")
        or device.get("device_type")
        or "UKey"
    )


def _ensure_localhost_certificate() -> tuple[str, str]:
    """Return a localhost TLS certificate/key pair, generating one if needed."""
    runtime_dir = Path(os.path.expanduser("~")) / ".bjca" / "certs"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    cert_path = runtime_dir / "server.crt"
    key_path = runtime_dir / "server.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)
    logger.info("Generated local TLS certificate: %s", cert_path)
    return str(cert_path), str(key_path)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Start the BJCA certificate environment service."""
    import argparse

    parser = argparse.ArgumentParser(
        description="BJCA Certificate Environment Service (macOS)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Listen host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=21061,
        help="Listen port (default: 21061)"
    )
    parser.add_argument(
        "--config", default="",
        help="Path to client_setup.ini config file"
    )
    parser.add_argument(
        "--log-level", default="info",
        choices=["trace", "debug", "info", "warning", "error"],
        help="Logging level"
    )
    parser.add_argument(
        "--allow-remote", action="store_true",
        help="DANGEROUS: Allow non-localhost connections"
    )
    parser.add_argument(
        "--pkcs11-module", default="",
        help="Path to PKCS#11 module (.dylib/.so)"
    )

    args = parser.parse_args()

    # Load configuration
    config = ServiceConfig()
    if args.config and os.path.exists(args.config):
        config = ServiceConfig.from_file(args.config)
    config.listen_host = args.host
    config.listen_port = args.port
    config.log_level = args.log_level
    if args.pkcs11_module:
        config.pkcs11_module_paths = [args.pkcs11_module]
    set_config(config)

    # Setup logging
    setup_logging(config)
    logger.info("Starting BJCA Certificate Environment Service v2.1.0")
    logger.info(f"  Listening on: {config.listen_host}:{config.listen_port}")
    logger.info(f"  WebSocket: wss://{config.listen_host}:{config.listen_port}/xtxapp")
    logger.info(f"  Health: http://{config.listen_host}:{config.listen_port}/health")

    # Security warning
    if args.allow_remote:
        logger.warning(
            "⚠️  Allowing remote connections! This bypasses the localhost-only "
            "security model of the local-only service."
        )

    # Create app
    app = create_app(config)

    # Graceful shutdown
    async def shutdown(app):
        logger.info("Shutting down...")
        # Close WebSocket connections
        ws_mgr = app.get("ws_manager")
        if ws_mgr:
            await ws_mgr.broadcast({
                "jsonrpc": "2.0",
                "method": "shutdown",
                "params": {},
            })

    app.on_shutdown.append(shutdown)

    # Start server with TLS; browser clients use wss:// on port 21061.
    import ssl as _ssl
    ssl_context = None
    cert_pem = os.path.join(os.path.dirname(__file__), "..", "config", "server.crt")
    key_pem = os.path.join(os.path.dirname(__file__), "..", "config", "server.key")
    for crt, key in [(cert_pem, key_pem), _ensure_localhost_certificate()]:
        if os.path.exists(crt) and os.path.exists(key):
            ssl_context = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(crt, key)
            break
    web.run_app(
        app,
        host=config.listen_host if not args.allow_remote else "0.0.0.0",
        port=config.listen_port,
        ssl_context=ssl_context,
        print=lambda _: None,
    )


if __name__ == "__main__":
    main()
