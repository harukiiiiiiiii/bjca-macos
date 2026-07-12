# BJCA UKey Service 2.1 安装指南

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

## 首次连接

1. 插入 UKey。
2. 在 Chrome 打开 `https://127.0.0.1:21061/health`。
3. 如果出现证书警告，点击“高级”，再点击“继续访问 127.0.0.1”。
4. 页面显示 `"status": "ok"` 且 `"devices_connected": 1`，表示服务和 UKey 正常。
5. 重新打开交易中心登录页，按原流程登录。

## 确认升级成功

打开 `https://127.0.0.1:21061/health`，确认：

- `status` 为 `ok`；
- `version` 为 `2.1.0`；
- 插入 UKey 后，`devices_connected` 为 `1`。

## 常见情况

### macOS 提示无法验证开发者

打开“系统设置”→“隐私与安全性”，找到被阻止的安装包，点击“仍要打开”，然后重新安装。

### 交易中心不显示 PIN 输入框

依次确认：

1. `https://127.0.0.1:21061/health` 可以打开；
2. `devices_connected` 为 `1`；
3. Chrome 扩展已启用；
4. 接受本地证书后，完全关闭并重新打开交易中心页面。

### PIN 输入错误

不要连续尝试。确认 PIN 后再输入；如果 UKey 已锁定，请联系证书签发或交易中心支持人员处理。
