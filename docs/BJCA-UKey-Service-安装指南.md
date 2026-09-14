# BJCA UKey Service 2.1.1 安装指南

## 安装前准备

- 一台 Mac，使用 Chrome 浏览器。
- Longmai GM3000 UKey。
- 知道自己的 UKey PIN。不要反复尝试不确定的 PIN，连续输错可能锁定 UKey。

## 从 2.0 升级

不需要卸载旧版。新版安装程序会停止旧服务、覆盖旧文件并重新启动服务。原有的本地证书和日志会保留，系统中不会同时运行两个 BJCA 服务。

1. 双击 `BJCA-UKey-Service.dmg`。
2. 双击 `BJCA-UKey-Service.pkg`。
3. 按安装器提示点击“继续”和“安装”。
4. 输入 Mac 登录密码。这里输入的是 Mac 密码，不是 UKey PIN。
5. 看到“安装成功”后关闭安装器。

## 首次安装

首次安装也使用上面的五个步骤。安装结束后，BJCA 服务会在后台自动运行，不需要手动打开应用。

## 加载 Chrome 扩展

升级自 2.0 时，如果 Chrome 中已有 `BJCA Certificate Bridge (macOS)`，先在扩展页面中将旧扩展删除，避免 Chrome 继续使用旧目录。这个操作只需做一次。

1. 在 Chrome 地址栏输入 `chrome://extensions` 并按回车。
2. 打开页面右上角的“开发者模式”。
3. 点击“加载已解压的扩展程序”。
4. 按 `Command + Shift + G`，输入 `/Users/Shared/BJCA-Chrome-Extension`。
5. 点击“打开”。
6. 确认页面出现 `BJCA Certificate Bridge (macOS)`，并且开关已打开。

以后安装更新时，安装器会覆盖这个固定目录。通常只需在扩展页面点击一次刷新按钮，或者重新启动 Chrome。

## 信任本地证书

本地服务通过 HTTPS（`https://127.0.0.1:21061`）与 Chrome 及交易网页通信，默认使用本台 Mac 生成的本地自签名证书（公钥证书文件位于 `~/.bjca/certs/server.crt`）。

在首次连接或新生成证书后，必须将该证书设置为当前用户的 SSL 信任，Chrome 扩展才能安全访问服务。网页上的“高级”→“继续访问”只是临时放行，检查页可能显示正常，但插件后台的健康请求仍可能因证书不受信任而失败，因此仅在检查页点击继续访问是不足够的。

> **升级说明**：从旧版本升级且本地保留了原有证书（`~/.bjca/certs/server.crt`）的用户，若此前已配置过信任，通常无需重复执行；若为首次安装、更换用户、或重新生成了新证书，请按以下步骤配置一次：

1. **确认服务已安装运行**：安装 `.pkg` 后本地服务会自动启动并生成公钥证书文件 `"$HOME/.bjca/certs/server.crt"`。
2. **信任本地证书**：打开终端（Terminal.app），复制并执行以下命令（为当前用户登录钥匙串配置 SSL 信任，无需 `sudo`）：

   ```bash
   security add-trusted-cert -r trustRoot -p ssl -k "$HOME/Library/Keychains/login.keychain-db" "$HOME/.bjca/certs/server.crt"
   ```

   *如系统弹出密码确认提示，请输入当前 Mac 登录密码授权。不要在命令中添加 -s 主机名限定。*
3. **完全重启 Chrome**：按快捷键 `Command + Q` 完全退出 Chrome 浏览器，然后重新打开 Chrome。
4. **验证证书状态**：在 Chrome 中打开 `https://127.0.0.1:21061/health`，页面应直接显示 JSON 数据，不再出现证书警告页。

## 首次连接

1. 插入 UKey。
2. 按照上方“信任本地证书”步骤确认证书已信任并已重启 Chrome。
3. 在 Chrome 中打开 `https://127.0.0.1:21061/health` 检查服务状态：
   - 页面直接打开无证书拦截，且包含 `"status": "ok"`，表示本地后台服务健康运行。
   - `"devices_connected": 1` 表示已成功识别插入的 GM3000 UKey（若为 0，表示尚未检测到 UKey，可先检查设备连接；设备识别与证书信任需要分别确认）。
4. 在 chrome://extensions 中确认 BJCA 扩展已启用，重新加载扩展后刷新交易中心登录页，检查连接提示，并按原流程登录验证。仅未出现提示框不能单独证明插件已正常运行。

## 确认升级成功

打开 `https://127.0.0.1:21061/health`，确认：

- 页面正常打开，无证书不安全警告；
- `status` 为 `ok`（服务运行健康）；
- `version` 为 `2.1.1`；
- 插入 UKey 后，`devices_connected` 为 `1`（已识别硬件）。

## 常见情况

### macOS 提示无法验证开发者

打开“系统设置”→“隐私与安全性”，找到被阻止的安装包，点击“仍要打开”，然后重新安装。

### 交易中心提示“本地服务无法安全连接”或不显示 PIN 输入框

依次确认：

1. 打开 `https://127.0.0.1:21061/health`：
   - 如果出现证书警告，说明 Chrome 尚未通过证书校验，请按[信任本地证书](#信任本地证书)步骤配置后重启 Chrome；
   - 如果提示无法访问或连接被拒绝，请检查本地服务是否已启动，以及 macOS 系统设置中的“登录项与扩展”后台项目；
   - 如果页面正常显示且 `status` 为 `ok`，但 `devices_connected` 为 `0`，请检查 UKey 是否插紧或指示灯是否正常；
2. 打开 `chrome://extensions` 确认 `BJCA Certificate Bridge (macOS)` 开关已开启；若扩展报错失效，点击重新加载按钮；
3. 完成上述检查后，重新打开交易中心页面。

### PIN 输入错误

不要连续尝试。确认 PIN 后再输入；如果 UKey 已锁定，请联系证书签发或交易中心支持人员处理。
