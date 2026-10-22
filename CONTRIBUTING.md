# 参与贡献

请先按 README 创建虚拟环境并运行现有测试。修复数据库逻辑时，使用合成 SQLCipher 夹具复现问题，不要提交真实数据库或聊天内容。修改数据库结构适配时，应验证正文编码、群聊前缀、收发路由、会话同步与事务失败行为。

提交前执行 `python -m unittest discover -s tests -v`、`python direct_app.py --self-test` 和 `python tools/check_publication.py`。若修改界面，请检查启动引导、错误反馈及空状态。构建命令见 README。

Issue 请描述 Windows/Python/微信版本、复现步骤与已脱敏错误信息。不要提交密钥、登录令牌、账号目录、完整启动 URL 或私人联系方式。不要上传真实聊天附件。第三方代码请注明来源并保留许可证。
