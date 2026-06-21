"""
bjca-service — macOS Native BJCA Certificate Environment Service

Architecture:
  Browser JavaScript
      ↓ WebSocket wss://127.0.0.1:21061/xtxapp
      ↓ HTTP POST  https://127.0.0.1:21061/api/<method>
  ┌─────────────────────────────────┐
  │  bjca_service/server.py        │  ← aiohttp async server
  │  bjca_service/api_handlers.py  │  ← JSON-RPC dispatcher
  │  bjca_service/device_manager.py│  ← USB Key enumeration
  │  bjca_service/smartcard.py     │  ← PC/SC wrapper
  │  bjca_service/pkcs11_bridge.py │  ← PKCS#11 interface
  │  bjca_service/crypto_ops.py    │  ← SM2/SM3/SM4 + RSA
  │  bjca_service/cert_manager.py  │  ← X.509 certificate ops
  └───────────┬─────────────────────┘
              ↓ pyscard / python-pkcs11 / CTK
  ┌─────────────────────────────────┐
  │  macOS CCID Driver (built-in)   │
  └───────────┬─────────────────────┘
              ↓ USB
  ┌─────────────────────────────────┐
  │  USB Key (ePass2000/3000, etc)  │
  └─────────────────────────────────┘
"""

__version__ = "1.0.0"
__author__ = "BJCA macOS Port"
