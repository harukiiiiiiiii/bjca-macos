# BJCA macOS 安全与可靠性修复设计

## 结论

本次修复采用“安全默认、显式兼容”的双模式架构。默认模式要求安装级认证令牌，并通过浏览器扩展和 Native Messaging 隔离网页与本地凭据；现有网页直连协议仅在显式启用 `--legacy-no-token` 时开放。所有密码学操作必须使用其声明的真实算法，任何依赖缺失、硬件不支持或验证不完整的情况都必须失败关闭。

## 目标

- 消除 `/data` 任意文件读取、跨站调用、本机服务冒用和无界资源消耗。
- 使 SM2、SM3、CSR、CMS/PKCS#7、证书验证和签名验签形成可验证闭环。
- 使 PKCS#11、PC/SC 与 Longmai GM3000 路径使用声明依赖的真实 API，并正确管理资源和 PIN。
- 使 Chrome 扩展能够在页面主世界工作，同时不向页面泄露认证令牌。
- 使源码安装和 DMG 安装使用确定的 Python 环境、正确用户、正确权限与可验证发布流程。
- 建立能真实失败、返回非零退出码并覆盖安全边界的自动化测试。

## 非目标

- 不承诺新增 GM3000 之外的硬件型号；已声明的 GM3000 PID 必须行为一致。
- 不伪装同步 ActiveX 调用。无法安全映射为异步调用的同步接口应明确报错。
- 不在缺少厂商 APDU 或 Token 写入能力时模拟成功。功能不受支持时返回稳定的“不支持”错误。
- 不以 SHA-256、ECDSA 或软件密钥冒充 SM3、SM2 或硬件签名。

## 总体架构

系统分为四个边界清晰的单元：

1. `bjca_service`：本地证书服务，负责认证、协议验证、设备串行化访问和密码学操作。
2. Chrome 扩展：页面主世界兼容层、隔离世界消息桥和后台安全代理。
3. Native Messaging Host：只向获准扩展提供本地认证材料，并代理扩展到本地服务的请求。
4. 安装与发布层：创建运行时、生成令牌、安装 Native Messaging 清单、部署 LaunchAgent 并验证服务。

默认数据流：

```text
网页主世界
  -> window.postMessage（固定协议、固定方法白名单）
隔离世界 content script
  -> chrome.runtime.sendMessage
扩展后台
  -> Native Messaging 获取短期认证上下文
  -> HTTPS 请求或认证 WebSocket
本地服务
  -> 设备/密码学实现
```

兼容数据流：

```text
受信网页
  -> 旧 WebSocket 协议
本地服务 --legacy-no-token
```

兼容模式仍执行 Origin 白名单、消息大小、方法参数和资源上限检查，并在启动日志与健康状态中明确标记为高风险模式。

## 安全边界

### 安装级令牌

- 首次启动以 `secrets.token_urlsafe(32)` 生成令牌。
- 令牌保存到 `~/.bjca/auth/token`，父目录权限为 `0700`，文件通过独占创建写入并设为 `0600`。
- 默认所有 `/api`、证书、配置和数据接口要求 `Authorization: Bearer <token>`。
- `/health` 无认证时只返回 `status`、`version` 和 `auth_required`，不得枚举设备或暴露路径。
- 比较令牌使用 `secrets.compare_digest`。
- 日志、异常、URL、WebSocket call id 和响应中不得包含令牌、PIN、PFX 密码或私钥。

### WebSocket 认证

- 默认模式使用 `Sec-WebSocket-Protocol` 传递一次性认证子协议，避免令牌出现在查询参数和访问日志中。
- 服务只回显固定协议名，不回显令牌。
- 扩展后台持有认证上下文，页面主世界不能直接获得令牌。
- `--legacy-no-token` 是唯一允许无令牌 WebSocket 的入口；仅接受精确 HTTPS Origin 白名单。

### HTTP 请求约束

- 有 `Origin` 的请求必须匹配精确主机或明确配置的子域后缀；缺失 Origin 的本机客户端仍必须提供令牌。
- `/api` 只接受 `application/json`，拒绝 `text/plain` JSON。
- 应用级请求体上限为 2 MiB；普通 JSON 字段上限为 256 KiB；PFX 和证书字段有独立 2 MiB 上限。
- `SOF_GenRandom` 最大请求 4096 字节；负数、非整数和超限值返回参数错误。
- PIN 失败由服务记录短期冷却状态，冷却期间不再向硬件发送验证命令，避免网页快速耗尽硬件重试次数。
- 对外错误只返回稳定错误码和通用消息，内部异常保留关联 ID 后写入日志。

### 静态文件

- 不再将 URL 片段直接与本地目录拼接。
- 默认只允许配置中声明的公开文件映射；初始映射仅包含 `client_setup.ini`。
- 映射目标必须是普通文件，解析后的真实路径必须位于公开数据根目录内。
- 绝对路径、路径分隔符、点段、百分号二次编码和符号链接逃逸全部拒绝。
- TLS 私钥、令牌、PFX、PEM 和用户主目录文件永远不能进入公开映射。

## 密码学设计

### SM3 与 SM2

- gmssl 不可用时，SM2、SM3、SM4 接口返回“算法不可用”，不使用 SHA-256 回退。
- SM2 私钥使用 `secrets.randbelow(n - 1) + 1` 生成。
- 每次软件签名使用独立的密码学安全随机 nonce，值域为 `[1, n-1]`。
- `SM2Engine` 同时持有匹配的私钥和公钥；签名使用 `sign_with_sm3`，验签使用 `verify_with_sm3`。
- SM2 加解密向 gmssl 传递字节，不传十六进制字符串。
- GM3000 普通签名与 SOF 签名统一计算 `SM3(ZA || M)`，不得只计算 `SM3(M)` 后标记为 SM3withSM2。
- SM4 只执行一次 PKCS#7 填充，校验 key/IV 长度，并拒绝无效填充。

### SM2 CSR

- CSR 的 SubjectPublicKeyInfo 使用 `id-ecPublicKey` 与 SM2 曲线 OID `1.2.156.10197.1.301`。
- CertificationRequestInfo 使用与返回私钥匹配的 SM2 公钥。
- CSR 签名算法使用 `1.2.156.10197.1.501`，签名值为 DER 编码的 `(r, s)`。
- 软件生成密钥仍保持现有 API 返回能力，但必须来自安全随机源，并只通过认证接口返回。
- 测试必须验证 CSR OID、CSR 自签名、私钥与 CSR 公钥一致性。

### CMS/PKCS#7

- CMS 验证必须解析 signer info、封装或分离内容、signed attributes 和 signer certificate。
- 存在 signed attributes 时验证 `messageDigest` 属性，并对规范化后的 signed attributes 验签；不存在时对内容验签。
- RSA、ECDSA 和 SM2 根据证书与 OID 选择真实算法；未知或不匹配算法失败。
- `valid` 只有在消息摘要、签名和证书信任链全部通过时为真。
- GM3000 CMS 签名使用 Token 返回的真实 SM2 签名构建 SignedData。
- PKCS#11 CMS 签名先获取证书和机制能力，再调用 Token 私钥，禁止传入空 PEM 私钥。

### Base64 与私密数据

- 所有外部 Base64 输入使用严格校验；无效字符、错误填充和空的必填值返回参数错误。
- 私钥、PIN、PFX 密码和认证令牌不缓存到全局对象，不进入日志或异常文本。

## 证书与硬件

### 证书验证

- 全部时间使用带 UTC 时区的 `datetime`。
- 信任链使用加载的系统/项目根证书验证签名、CA 约束、路径长度和有效期。
- 未配置吊销信息时返回 `revocation_status: not_checked`，不得声称已完成 CRL/OCSP 验证。
- 自签名终端证书、未知根和过期证书默认无效。
- 普通验签根据证书算法与请求算法处理 SM2 原始 `r||s`、DER ECDSA 和 RSA 签名。

### PKCS#11

- 以项目锁定的 python-pkcs11 API 为准，查询使用 `Attribute.CLASS`、`Attribute.ID`、`Attribute.LABEL` 等真实属性。
- Slot 元数据使用 `slot_description`、`manufacturer_id` 和 flags，不读取不存在的字段。
- 登录通过 `token.open(user_pin=...)` 建立认证会话，不调用不存在的 `session.login()`。
- 签名机制必须存在于 Token 的机制集合；SM3/SM2 不得映射为 SHA-256/ECDSA。
- `open_session()` 失败必须向调用方传播失败，`DeviceManager` 不得仍返回成功。
- 证书/PFX 导入只有在对象创建并读回验证后才增加成功计数；Token 不支持写入时返回“不支持”。
- PIN 修改仅在实际调用 `session.set_pin()` 成功后返回成功。

### PC/SC 与 GM3000

- `createConnection()` 后必须调用 `connect()`；ATR 统一转换为 `bytes`。
- 所有临时连接和 HID probe 使用 `try/finally` 或上下文管理器关闭。
- GM3000 使用枚举结果的设备 path 打开，覆盖已声明的全部 PID，不再固定为 `0xE618`。
- 传输尊重调用者 timeout，校验 report 长度、序号和写入长度；状态字只从协议定义位置提取。
- 多包发送根据 APDU 长度生成任意所需 continuation report，不产生超过 65 字节的 HID report。
- 设备初始化失败、PIN 失败、拔出和服务关闭都执行统一会话清理。
- 服务不保存明文 PIN；成功登录只保存不可伪造的会话状态和有限有效期。
- 所有硬件操作通过单一设备队列串行执行，并从 aiohttp 事件循环移到工作线程，避免阻塞其他连接。

## Chrome 扩展

- 拆分 `page_bridge.js`、`content_bridge.js` 和 `background.js`。
- `page_bridge.js` 在 MAIN world 运行，不访问 `chrome.*`；只发送带随机 correlation id 的固定结构消息。
- `content_bridge.js` 在隔离世界运行，校验消息来源、方向、方法白名单、参数大小和 correlation id，再调用扩展 runtime。
- `background.js` 校验 sender tab/frame URL，并只允许 manifest 白名单中的站点。
- Native Messaging 清单只允许发布扩展 ID；Host 只返回当前用户令牌，不接受任意文件路径或命令。
- 页面兼容方法明确返回 Promise；同步 ActiveX 调用返回清晰的不支持错误，不让 Promise 被当作数值或字符串。
- WebSocket 代理只拦截明确配置的 BJCA 旧地址，不匹配任意包含 `127.0.0.1` 的 URL。
- 删除递归的 `navigator.plugins` getter。
- manifest 不引用缺失资源；发布构建必须验证所有图标、脚本和 Native Messaging 文件存在。

## 配置、安装与发布

### 配置

- 配置读取按 UTF-8-SIG、UTF-8、GB18030 顺序尝试，并对解析错误给出文件路径和明确错误。
- `ServiceConfig.from_file()` 解析 `[server]` 和 `[pkcs11]`，保存与读取字段对称。
- CLI 显式参数优先于配置；未提供 CLI 参数时保留配置值。
- DMG 与源码安装使用同一配置路径，并通过 `--config` 明确传递。
- 版本只从 `bjca_service.__version__` 读取，服务、扩展和构建脚本在发布检查中必须一致。

### Python 与依赖

- 源码安装创建专用虚拟环境，并始终使用选定解释器的 `python -m pip`。
- 运行依赖使用精确版本锁文件；核心依赖包含 hidapi 和 asn1crypto。
- DMG 不再复制构建者任意 user-site。发布构建要求显式提供目标架构的受控 Python runtime，并把解释器与依赖一起打包。
- 构建产物标记目标架构；arm64 与 x86_64 分别构建，安装前验证机器架构。
- 缺失依赖、错误 Python ABI 或缺失 runtime 时构建直接失败。

### 安装与 LaunchAgent

- Installer 以 `/dev/console` 确定登录用户；`USER=root` 不得安装到 root 的 LaunchAgent。
- 系统级 payload 所有权为 `root:wheel`，普通用户不可修改全局源码和 vendor。
- 用户运行目录和令牌仅归目标用户所有。
- `INSTALL_DIR` 在生成 wrapper、plist 和配置路径时保持一致，不出现硬编码回退。
- launchctl bootstrap、kickstart 或健康验证失败时安装返回非零，不打印成功。
- TLS 证书生成、信任或固定策略在安装结果中明确验证；扩展代理不得依赖用户手工忽略证书错误。

### 发布真实性

- 开发构建允许无签名，但产物名称和日志必须标为 development。
- 发布构建要求 Developer ID Installer/Application 身份、notarization 凭据和 stapling；缺少任一项即失败。
- pkg 重打包后再次验证 BOM 所有权、签名和 Gatekeeper 结果。

## 错误处理与兼容性

- JSON-RPC 参数错误使用 `-32602`，认证失败使用独立服务错误码，硬件不支持与硬件暂不可用使用不同错误码。
- WebSocket 非 JSON 消息始终返回一次解析错误；删除不可达的重复异常分支。
- Token 或设备错误不直接把底层异常文本返回网页。
- 兼容模式不改变既有 wire response 外形，但仍应用输入限制和错误码。
- 默认安全模式可有意拒绝旧网页直连；用户必须安装扩展或显式启用兼容模式。

## 测试策略

### 单元测试

- 路径规范化：绝对路径、编码斜杠、点段、双重编码、符号链接与白名单文件。
- 认证：缺失、错误和正确令牌；Origin 缺失、恶意 Origin 与允许 Origin。
- JSON：错误 Content-Type、非对象 JSON、超大请求、超大随机数和严格 Base64。
- SM2/SM3：标准向量、签名验签闭环、加解密闭环、安全 nonce 注入测试。
- CSR：曲线/签名 OID、公私钥一致性和 CSR 验签。
- CMS：有效签名、篡改内容、篡改签名、错误 messageDigest、未知根和过期证书。
- PKCS#11/PCSC：使用符合真实库接口的 fake token/reader，验证登录、机制、关闭和错误传播。
- GM3000：多 PID、report 边界、多包 APDU、timeout、序号和清理。
- 配置：仓库 UTF-8 文件、GB18030 文件、server/pkcs11 节和保存读取对称性。
- 扩展：manifest 资源检查、消息来源检查、方法白名单和递归 getter 不存在。

### 集成测试

- 启动临时 aiohttp 服务，验证恶意 Origin 的 `text/plain` 请求不执行任何方法。
- 验证 `/data/%2Fetc%2Fhosts`、编码相对路径和 TLS key 请求均失败。
- 验证认证扩展代理能完成健康检查、设备枚举和签名请求。
- 验证 WebSocket 认证、兼容模式警告及非法 JSON 响应。
- 运行打包检查，验证 Python ABI、架构、BOM 所有权、manifest 文件和发布签名门槛。

### 测试入口

- `python3 tests/test_service.py` 和标准测试运行器都必须在任一失败时返回非零。
- 硬件测试明确标记为 skipped，不计为 passed。
- CI 至少运行 Python 3.9 与项目支持的最高 Python 版本；发布任务分别验证 arm64 与 x86_64。

## 实施顺序

1. 建立可靠测试入口与安全漏洞回归测试。
2. 修复静态文件、认证、Origin、请求限制和 WebSocket 错误处理。
3. 修复 SM2/SM3、CSR、CMS 和证书验证。
4. 修复 PKCS#11、PC/SC、GM3000 与设备生命周期。
5. 重构扩展消息桥和 Native Messaging Host。
6. 修复配置、源码安装、DMG runtime、权限和发布检查。
7. 执行全量测试、恶意输入复测、安装产物审计和逐项验收。

## 验收标准

- 所有 23 项审查发现均有独立回归测试或构建检查。
- 任意文件读取、恶意 Origin API 调用和伪造 CMS 均被自动化测试拒绝。
- SM2 签名、验签、加解密和 CSR 使用正确 OID 与匹配密钥。
- PKCS#11 0.9.x、PC/SC fake 集成测试覆盖真实 API 形状，不再调用不存在的成员。
- 仓库提供的配置文件能够被源码安装和 DMG 安装成功读取。
- Chrome 扩展 manifest 的全部资源存在，主世界与隔离世界消息链路通过测试。
- 安装产物不依赖目标机任意 Python，不把 LaunchAgent 安装给 root，不留下普通用户可写的系统 payload。
- 开发构建明确标识未签名；发布构建在未签名或未公证时失败。
- 全量测试退出码、跳过统计和日志均能准确反映结果。

