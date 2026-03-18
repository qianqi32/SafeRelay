# SafeRelay - 安全私聊机器人

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/qianqi32/SafeRelay)

## 🔥 项目简介

SafeRelay 是一个轻量级的 Telegra 私聊机器人，专注于防骚扰和高效沟通。它采用 **单对单** 模式，支持人机验证、联合封禁、自定义欢迎消息和自动回复等多个功能。

机器人采用 Serverless 架构，无需服务器即可部署，零成本运行！

部署教程请查看 [DEPLOY.md](./DEPLOY.md)。

## ✨ 功能特性

- **消息中转** — 用户↔管理员双向转发，支持编辑同步
- **人机验证** — 支持 Cloudflare Turnstile 和本地题库验证，防机器人骚扰
- **联合封禁** — 接入中心化封禁系统，恶意用户一次封禁全网拦截
- **欺诈检测** — 本地欺诈数据库，自动识别并拦截可疑用户
- **白名单** — VIP用户跳过所有检查，直接转发
- **本地管理** — 拉黑/解封/重置验证，回复消息即可操作
- **自动消息** — 自定义欢迎消息与自动回复（带10分钟冷却）
- **图形面板** — Inline Keyboard 菜单，配置一键完成
- **广播推送** — 向所有用户群发消息，支持 HTML，24小时冷却，分批发送
- **编辑同步** — 用户和管理员编辑消息实时同步
- **消息统计** — 自动统计每日消息数和活跃用户数
- **零成本运行** — Cloudflare Workers 免费额度长期稳定运行

## 🤖 管理员指令

所有指令建议直接 **回复 (Reply)** 用户转发过来的消息使用，机器人会自动提取目标用户 ID。

| 指令 | 作用 | 示例 |
|:----:|:-----|:----:|
| 回复消息 | 直接回复内容给用户 | （直接打字发送） |
| `/help` | 显示帮助信息 | `/help` |
| `/menu` | 打开管理面板 | `/menu` |
| `/ban` | 封禁用户（永久） | 回复某条消息发送 `/ban` 或 `/ban 123456` |
| `/unban` | 解封用户 | 回复某条消息发送 `/unban` 或 `/unban 123456` |
| `/reset` | 重置验证（强制重新验证） | 回复某条消息发送 `/reset` 或 `/reset 123456` |
| `/welcome` | 设置欢迎消息 | `/welcome 你好！请先完成验证` |
| `/autoreply` | 设置自动回复 | `/autoreply 客服已收到消息` |
| `/broadcast` | 向所有已验证用户广播消息 | `/broadcast 系统维护通知` |
| `/addwhite` | 添加用户到白名单 | 回复某条消息发送 `/addwhite` 或 `/addwhite 123456` |
| `/delwhite` | 从白名单删除用户 | 回复某条消息发送 `/delwhite` 或 `/delwhite 123456` |
| `/checkwhite` | 检查白名单状态 | 回复某条消息发送 `/checkwhite` 或 `/checkwhite 123456` |
| `/listwhite` | 列出所有白名单用户 | `/listwhite` |
| `/bcancel` | 取消进行中的广播 | `/bcancel` | 


## 🧠 工作原理

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   用户私聊   │ --> │   机器人    │ --> │   管理员    │
│  (需验证)   │     │  (验证/转发) │     │  (直接回复) │
└─────────────┘     └─────────────┘     └─────────────┘
       ^                                      │
       └──────────────────────────────────────┘
                    (回复自动回传)
```

1. 新用户首次发消息 → 触发人机验证
2. 验证通过 → 消息转发给管理员
3. 管理员回复 → 自动回传给用户
4. 已验证用户 → 消息直接转发

## 🛡️ 安全特性

- **联合封禁**：接入第三方封禁系统，自动拦截恶意用户
- **欺诈检测**：本地欺诈数据库，实时比对可疑用户
- **防刷屏保护**：5 秒内最多 5 条消息，防止消息轰炸
- **人机验证**：Cloudflare Turnstile 验证，有效阻止机器人

## ⚠️ 注意事项

1. **验证延迟**：Cloudflare KV 具有最终一致性，验证通过后可能需要 30 秒才能在全球所有边缘节点生效
2. **白名单优先级**：白名单用户跳过所有检查（包括验证、黑名单、欺诈检测）
3. **消息映射过期**：消息转发映射关系保存 48 小时，超过后无法回复旧消息
4. **广播冷却**：广播功能有 24 小时冷却时间，每次最多发送 500 条消息
5. **编辑限制**：Telegram 限制只能编辑 48 小时内的消息

## 🎯 适用场景

适合：
- 客服机器人
- 匿名投稿机器人
- 私聊中转机器人
- 反馈收集机器人
- 社群接待机器人

## 🛠 技术栈

- JavaScript (ES6+)
- Telegram Bot API
- Cloudflare Workers + KV
- Cloudflare Turnstile

## 📂 项目结构

```
SafeRelay/
├── worker.js          # 主程序代码
├── DEPLOY.md          # 部署指南
├── README.md          # 项目说明
├── LICENSE            # GPL-3.0 许可证
└── data/
    └── fraud.db       # 欺诈用户数据库
```

### 欺诈数据库

`data/fraud.db` 文件包含已知的欺诈用户ID列表，每行一个用户ID。机器人会自动检测并拦截这些用户。

**自定义欺诈数据库**：
1. 编辑 `data/fraud.db` 文件
2. 每行添加一个用户ID
3. 提交到 GitHub 后约1小时生效（或重启Worker立即生效）

## 🙏 致谢

本项目基于以下开源项目开发，并借鉴了诸多优秀实践：

| 项目 | 作者 | 许可证 | 主要贡献 |
|:----:|:----:|:------:|:---------|
| [NFD](https://github.com/LloydAsp/nfd) | LloydAsp | GPL-3.0 | 核心架构、消息中转 |
| [NFD 3.0](https://www.nodeseek.com/post-545453-1) | NodeSeek | GPL-3.0 | Turnstile 验证 |
| [RelayGo](https://github.com/abcxyz-123456/RelayGo) | abcxyz-123456 | GPL-3.0 | 联合封禁、管理面板 |
| [telegram-verify-bot](https://github.com/Squarelan/telegram-verify-bot) | Squarelan | GPL-3.0 | 白名单、欺诈检测 |
| [telegram_private_chatbot](https://github.com/jikssha/telegram_private_chatbot) | jikssha | MIT | 本地题库、验证机制、安全实践、部署流程 |

感谢上述项目的作者们！❤️

## 📜 许可证

本项目基于 [NFD](https://github.com/LloydAsp/nfd) 开发，采用 [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) (GPL-3.0) 开源协议。

作为 GPL-3.0 许可软件的衍生作品，本项目遵循相同的许可证条款。您可以自由使用、修改和分发，但必须遵守 GPL-3.0 的要求，包括：
- 保留版权声明
- 使用相同的许可证（GPL-3.0）发布衍生作品
- 提供源代码

详见 [LICENSE](./LICENSE) 文件。

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/image?repos=qianqi32/SafeRelay&type=date&legend=top-left)](https://www.star-history.com/?repos=qianqi32%2FSafeRelay&type=date&legend=top-left)
