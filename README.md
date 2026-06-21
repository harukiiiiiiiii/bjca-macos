# BJCA 证书环境 — macOS 原生实现

在 macOS 上运行 BJCA 证书环境，通过 HID 协议直接与龙脉 GM3000 USB Key 通信，
提供交易平台浏览器侧所需的 HTTPS + WebSocket JSON-RPC 服务。无需 Windows、
无需虚拟机、无需额外厂商驱动。

## 快速开始

```bash
cd bjca-macos

# 安装依赖
pip3 install aiohttp aiohttp-cors gmssl cryptography pyOpenSSL hidapi

# （可选）智能卡支持
brew install opensc
pip3 install pyscard python-pkcs11

# 启动服务
python3 -m bjca_service.server
```

服务默认监听 `https://127.0.0.1:21061`，WebSocket 路径 `/xtxapp`。

## 验证

```bash
# 健康检查
curl -sk https://127.0.0.1:21061/health

# 列出设备
curl -sk -X POST https://127.0.0.1:21061/api \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"list_devices","params":{},"id":1}'

# 签名
curl -sk -X POST https://127.0.0.1:21061/api \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"sign","params":{"data":"SGVsbG8=","pin":"你的PIN"},"id":1}'
```

## TLS 证书

服务使用本机自签名证书。首次运行时会自动生成到
`~/.bjca/certs/server.crt` 和 `~/.bjca/certs/server.key`。
浏览器连接前可以信任此证书：

**方法 A — 信任证书（推荐）:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.bjca/certs/server.crt
```

**方法 B — Chrome 允许不安全 localhost:**
1. 打开 `chrome://flags/#allow-insecure-localhost`
2. 设为 Enabled，重启 Chrome

两种方法完成后，访问 `https://127.0.0.1:21061/health` 确认不再报证书错误，
然后刷新证书登录页面即可。

## API

所有接口兼容交易平台证书控件常用的 JSON-RPC 2.0 调用。

| 方法 | 说明 |
|------|------|
| `health` | 健康检查 |
| `list_devices` | 列出 USB Key 设备 |
| `init_device` | 初始化设备（PIN 验证） |
| `list_certificates` | 列出证书 |
| `get_certificate` | 导出证书详情 |
| `sign` | SM2 签名（SM3withSM2） |
| `hash` / `sm3_hash` | 哈希计算 |
| `verify` / `verify_pkcs7` | 签名验证 |
| `list_containers` | 列出密钥容器 |
| `change_pin` | 修改 PIN |
| `list_seals` / `get_seal_image` | 电子印章 |
| `generate_csr` | 生成证书请求 |
| `base64_encode` | Base64 编码 |

详细 API 文档见[原 README 末尾](#api-文档)。

## 支持的 USB Key

| 型号 | 厂商 | 传输 | 状态 |
|------|------|------|------|
| GM3000 | 龙脉 Longmai | HID | ✅ 完整支持 |
| ePass2000/3000 | 飞天 Feitian | CCID | ⚠️ 需 PC/SC |
| USK218 | 握奇 WatchData | CCID | ⚠️ 需 PKCS#11 |

## 项目结构

```
bjca_service/           # 核心服务
  server.py             # aiohttp HTTPS + WebSocket
  api_handlers.py       # JSON-RPC 分发器
  device_manager.py     # 设备管理（GM3000 优先）
  longmai_gm3000.py     # GM3000 原生 HID 驱动
  longmai_hid.py        # HID 设备发现
  cert_manager.py       # X.509 证书管理（含 SM2）
  crypto_ops.py         # SM2/SM3/SM4 国密
  config.py             # 配置
  smartcard.py          # PC/SC 智能卡
  pkcs11_bridge.py      # PKCS#11 桥接
config/                 # INI 配置
extensions/chrome/      # Chrome 扩展（可选）
```

## 许可

MIT License — 基于互操作性考虑开发，与 BJCA/北京数字认证无官方关联。
