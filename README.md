# 微信数据库编辑器 · WeChat DB Editor

## 直接下载使用

**[下载 Windows x64 便携版 v2.0.0](https://github.com/TTTAAXXTTT/wechat-db-editor/releases/download/v2.0.0/WeChat-DB-Editor-Windows-x64-v2.0.0.zip)** · [发布说明及 SHA-256 校验](https://github.com/TTTAAXXTTT/wechat-db-editor/releases/tag/v2.0.0)

完整解压后运行 `WeChatDBEditor.exe`（直接编辑）或 `WeChatDBCopyEditor.exe`（副本编辑）。无需安装 Python。直接编辑前请备份源数据库。


Windows 本地微信 4.x 文本数据库编辑工具，提供浏览器界面、会话浏览、搜索、文本修改、直接新增与完整性检查。页面与服务均在本机运行，开源代码采用 MIT 许可，无激活限制。

> 直接模式会原地修改源数据库，没有自动备份或撤销。操作前请自行备份完整账号目录，并完全退出微信。请仅处理本人或获得授权的数据。

## 两种运行模式

| 模式 | 启动 | 写入位置 | 功能 |
|---|---|---|---|
| 直接编辑 | `python direct_app.py` | 所选账号源库 | 修改文本、新增本人/对方文本、同步最后消息摘要、修复旧版新增气泡方向 |
| 副本编辑 | `python app.py` | 独立快照编辑层 | 建立加密原始快照、编辑/删除、审计与撤销、校验原始快照；不会自动回写源库 |

原有副本工作流保留；日常使用的直接编辑界面为 `direct_app.py`。两种模式都支持会话浏览、分页、搜索与校验。

## 从源码安装

当前支持 Windows 10/11 x64，使用 Python 3.14 x64。SQLCipher wheel 和 Windows 内存读取实现是平台依赖，不承诺 Linux/macOS 支持。微信版本变化可能使数据库结构或密钥提取失效；现有实现面向微信 4.x，尚未对所有版本进行验证。

```powershell
git clone https://github.com/TTTAAXXTTT/wechat-db-editor.git
cd wechat-db-editor
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe direct_app.py
```

程序自动打开默认浏览器的 `127.0.0.1` 随机端口页面。命令行添加 `--no-browser` 会打印本次启动 URL；请复制完整链接，URL 中的令牌仅用于本地会话。不要直接双击 HTML 文件。

## 直接编辑流程

1. 自行备份完整账号目录。完全退出当前已登录的微信，再重新打开并停在未登录界面。
2. 启动编辑器并手动选择账号目录，例如 `D:\WeChatData\wxid_example`，其下应有 `db_storage`。项目不预填或保存个人路径。
3. 点击“开始等待登录并提取”，收到提示后再登录微信。提取器仅查询、读取当前 Windows 会话中的 `Weixin.exe` / `WeChat.exe`；候选密钥必须对所需消息库、联系人库与会话库逐库只读验真。
4. 提取成功后保持编辑器打开，从微信菜单完全退出微信，确认所有相关进程已结束。
5. 点击“只读检查目录”，再点击“直接打开源数据库”。也可手动输入 64 位十六进制密钥或主动导出的 `WCKEY1:` 密钥包。
6. 选择会话修改文本；或新增本地文本，选择本人、私聊对方或已有群成员，并填写本机时间。确认提示后写入。
7. 退出编辑器，重新打开微信核对显示。建议先在测试账号或自行制作的数据库副本中验证。

## 备份、副本与支持范围

- 副本模式先复制加密原始文件并生成 SHA-256 清单，再建立独立编辑层；原始快照只读。审计与撤销只适用于副本编辑层。
- 直接模式保存后执行 WAL checkpoint 和 `quick_check`；校验通过并不等于可以撤销，也不替代操作前备份。
- 支持普通文本和 Zstandard 压缩正文，保留群聊发送者前缀。修改最后一条消息时同步会话摘要；新增最新消息时同步可用的最后消息字段。
- 新增文本带本地插入标记，工具不调用微信发送接口；不会主动修改对方、手机或其他电脑的聊天记录。不同微信版本的客户端行为应由使用者自行验证。
- 直接模式不提供删除。图片、语音、视频、转账、红包等类型不会被伪装成普通文本。
- 不重建微信私有 `MMFtsTokenizer` 全文索引：聊天显示可能已更新，而微信内置搜索仍命中旧词或暂时搜不到新词。
- 自动密钥提取依赖微信登录阶段的 WCDB 对象；超时后可按上述顺序重试。工具不会自动结束或启动微信。

## 隐私与脱敏

仓库只包含程序源码、文档、许可与运行时生成的合成测试夹具，不包含聊天数据库、导出的密钥包、私人联系方式、个人配置或授权私钥。页面无外部字体、脚本或图片；HTTP 服务只绑定回环地址，API 使用随机会话令牌。提取的密钥只保留在内存中，关闭数据库或退出时覆盖清除；只有用户主动导出时才显示可复制的密钥包。

运行日志位于 `%LOCALAPPDATA%\WeChatCopyEditor\app.log`，可能记录本机错误上下文。提交 issue 前请检查日志、截图与路径，删除聊天内容和密钥；不要公开完整本地启动 URL。不要把运行数据放进源码仓库。详见 [SECURITY.md](SECURITY.md)。

## 开发与验证

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe direct_app.py --self-test
.\.venv\Scripts\python.exe tools/check_publication.py
```

测试在临时目录构建合成 SQLCipher 数据库，覆盖直接写入、压缩与前缀、收发气泡路由、会话摘要同步、密钥包验真、内存清理、副本审计撤销以及 HTTP 访问与启动行为。不会读取真实聊天或调用真实密钥扫描。GitHub Actions 在 Windows 上运行测试和打包检查。

## 打包 Windows EXE

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe tools/build.py
```

生成 `dist/WeChatDBEditor.exe`。运行 `tools/build.py --mode copy` 可生成 `dist/WeChatDBCopyEditor.exe`。构建会生成包含项目及依赖许可的离线页面，然后由 PyInstaller 打包，最后执行 EXE 自检。构建输出、数据库和日志默认被 Git 忽略。

## 项目结构

```text
app.py                  数据库核心、HTTP API、副本入口
direct_app.py           直接编辑入口
wechat_key_extract.py   Windows 只读密钥候选提取
static/                 两种模式界面及样式
tests/                  合成数据库与 HTTP 回归测试
tools/                  构建、许可页面与发布扫描
licenses/               第三方 Apache-2.0 全文
.github/workflows/      Windows 测试与构建
```

## 许可

本项目原创代码采用 [MIT](LICENSE) 许可；`wechat_key_extract.py` 中的 Apache-2.0 适配代码及依赖遵循原有条款。参见 [第三方说明](THIRD_PARTY_NOTICES.md) 与 [贡献指南](CONTRIBUTING.md)。本项目与腾讯或微信无隶属关系。

