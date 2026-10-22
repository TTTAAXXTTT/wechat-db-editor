# 第三方组件与来源

本项目自行编写的编辑器、界面和测试代码采用根目录 MIT 许可证。以下第三方代码和依赖仍遵循各自许可；MIT 不覆盖其原有版权与许可要求。

| 组件 | 用途 | 来源与许可 |
|---|---|---|
| sqlcipher3 0.6.2 | SQLCipher Python DB-API | https://github.com/coleifer/sqlcipher3 · MIT |
| SQLCipher Community Edition | 加密 SQLite | https://github.com/sqlcipher/sqlcipher · BSD-style；按所用发行包附带许可分发 |
| python-zstandard 0.25.0 | WCDB 压缩文本 | https://github.com/indygreg/python-zstandard · BSD |
| PyInstaller 6.22.3 | 可选 Windows 打包 | https://pyinstaller.org/ · GPL-2.0 with bootloader exception |
| Python 3.14 | 运行时 | https://www.python.org/ · PSF |
| wechatauto-replica 1.2.2.6 | WCDB Config.Cipher 解码适配 | https://github.com/fanyuantaier/wechatauto-replica · Apache-2.0 |
| wx-cli v0.3.0 | 旧版严格 raw-key/salt 字面量解析适配 | https://github.com/jackwener/wx-cli · Apache-2.0 |

`wechat_key_extract.py` 包含对后两者思路及代码的 Python 缩小适配和修改：限制为同一 Windows 会话的微信进程，只申请查询与读取权限，增加候选约束、数据库首页 HMAC 验证及逐库只读打开校验。原有来源标记保留在文件顶部，Apache-2.0 全文保存在 `licenses/` 中。未包含上游二进制、DLL 或完整项目。

发行二进制时，`tools/build.py` 会从实际安装的 wheel 收集依赖许可并生成离线许可页面；PyInstaller 同时收集 SQLCipher 与 Zstandard 的运行资源。OpenSSL、SQLite、libzstd 等传递组件的许可，以安装 wheel 中附带的完整许可为准。
