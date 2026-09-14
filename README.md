# BJCA 证书环境 — macOS 原生实现

在 macOS 上运行 BJCA 证书环境，通过 HID 协议直接与龙脉 GM3000 USB Key 通信，
提供交易平台浏览器侧所需的 HTTPS + WebSocket JSON-RPC 服务。无需 Windows、
无需虚拟机、无需额外厂商驱动。

当前只承诺支持龙脉 Longmai GM3000。其它厂商、其它型号或同厂不同固件可能无法使用。

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

> **说明**：以下 `curl -sk` 命令仅用于快速检测本地服务进程是否存活与端口连通性（`-k` 参数会跳过证书校验），并不代表证书已被 Chrome 浏览器信任。

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

服务使用本机自签名证书。首次运行或安装后会自动生成到
`~/.bjca/certs/server.crt` 和 `~/.bjca/certs/server.key`。
浏览器连接前必须让 Chrome 信任此本地生成的证书，否则交易页面无法建立
`wss://127.0.0.1:21061/xtxapp` 连接，扩展后台检查也会报错（`Failed to fetch`）。

### 为什么检查页能打开，插件仍提示连接失败

- **点击继续访问不足以保证插件可用**：网页上的“高级”→“继续访问”只是临时放行，检查页可能显示正常，但插件后台的健康请求仍可能因证书不受信任而失败。因此，看到 /health 返回 JSON 并不能确认插件已经连接成功。
- **保护私钥安全**：切勿将 `server.key` 分发给其他机器，仅信任由本用户当前 Mac 生成的公钥证书 `server.crt`。

### 信任当前用户证书步骤

1. **先启动或安装服务**：确保本地已生成证书文件 `"$HOME/.bjca/certs/server.crt"`（如未启动过，可运行一次服务或完成安装）。
2. **导入到当前用户登录钥匙串并设置 SSL 信任**：在终端执行以下命令（无需 `sudo`，无需修改系统级 `System.keychain`）：

   ```bash
   security add-trusted-cert -r trustRoot -p ssl -k "$HOME/Library/Keychains/login.keychain-db" "$HOME/.bjca/certs/server.crt"
   ```

   *如 macOS 弹出授权窗口，请按系统提示确认。不要在上面的导入命令中添加 -s 主机名限定：Chrome 会忽略这类信任规则。*
3. **完全退出并重新打开 Chrome**：若 Chrome 正在运行，按快捷键 `Command + Q` 完全退出 Chrome，然后重新启动。
4. **验证证书信任**：在 Chrome 中打开 `https://127.0.0.1:21061/health`，页面应直接正常展示 JSON 内容，**不再出现任何安全警告或拦截提示**。
5. **验证插件与交易平台**：在 chrome://extensions 中确认 BJCA 扩展已启用，重新加载扩展后刷新交易平台，检查是否仍有连接或扩展失效提示，再按原流程登录验证。

#### （可选）证书诊断命令说明

如需在终端查看证书验证状态，可执行诊断命令：

```bash
security verify-cert -c "$HOME/.bjca/certs/server.crt" -p ssl -s 127.0.0.1
```

*此处 -s 127.0.0.1 用于校验主机名，不是设置导入时的信任范围。该命令通过只说明 macOS 的验证结果；还需检查 Chrome 直接打开 /health 时无证书警告，并按上面的步骤验证插件与交易平台连接。*

## API

所有接口兼容交易平台证书控件常用的 JSON-RPC 2.0 调用。

| 方法 | 说明 |
| ------ | ------ |
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

不承诺支持飞天、握奇、其它 CCID/PKCS#11 UKey，也不承诺支持非 GM3000 的龙脉设备。

## GM3000 PIN 算法

`v1.0.2` 起，GM3000 的 PIN block 使用 Linux/RK 端真机验证过的派生方式：

```text
SM4 key = SHA1(PIN + NUL padding 到至少 16 字节)[:16]
plain   = uint16_le(8) || challenge8 || 0x80 || 0x00 * 5
block   = SM4-ECB-Encrypt(SM4 key, plain)[:16]
```

旧版曾使用本机私有 `pin_keys.json` 映射或 `SM3(PIN)[:16]` fallback。公开版不再依赖
`pin_keys.json`，也不会把任何个人 PIN 映射写入仓库或安装包。

## 安全与会话说明

- **公开文件访问**：`/data/{filename}` 仅允许访问配置中显式注册的公开文件；禁止任意路径遍历及目录逃逸。
- **Origin 访问控制**：仅允许受信任的交易平台 HTTPS Origin（即 `jspec.com.cn`、`www.jspec.com.cn` 以及 `*.sgcc.com.cn`）及本地 Chrome 扩展（HTTP 接口）；无 Origin 的本地 CLI/原生程序同样允许访问，未授权来源将被严格阻断。
- **无安装 Token 限制**：本地服务不要求安装授权 Token；此兼容性修复不对无 Origin 的本地程序进行身份认证，也不新增安装授权 Token 要求。
- **WebSocket 会话绑定**：WebSocket Token 与具体连接 Socket 绑定；Socket 重连、断开或会话超时（30分钟）后旧 Token 立即失效，必须重新认证登录。
- **HTTP 会话作用域**：HTTP 会话具备独立作用域，登出操作仅能注销请求中显式携带的自身对应 Token，无法跨连接或跨作用域注销其他会话；但本服务不保证已持有他人合法 HTTP Token 的本地程序无法使用该 Token。

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
