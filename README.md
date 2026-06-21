<div align="center">

# SafeRelay

## 安全私聊机器人 — 防骚扰 · 零成本 · Serverless

[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow?logo=javascript&logoColor=white)](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript) [![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-100K%2Fday-orange?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/) [![Telegram Bot](https://img.shields.io/badge/Telegram%20Bot-API%208.0+-blue?logo=telegram&logoColor=white)](https://core.telegram.org/bots/api) [![License](https://img.shields.io/badge/License-GPL--3.0-green)](LICENSE)

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/qianqi32/SafeRelay)
[![Deploy with Wrangler](https://img.shields.io/badge/部署-Wrangler_CLI-1DA1F2?style=for-the-badge&logo=cloudflare&logoColor=white)](./DEPLOY.md#%E6%96%B9%E6%A1%88-bwrangler-cli-%E9%83%A8%E7%BD%B2)

</div>

---

## ✨ 功能特性

| 模块 | 说明 |
| ---- | ---- |
| **消息中转** | 用户↔管理员双向转发，支持编辑同步与话题模式 |
| **人机验证** | Cloudflare Turnstile + 本地题库双重验证，有效拦截机器人 |
| **联合封禁** | 接入中心化封禁系统，恶意用户一次封禁全网拦截 |
| **欺诈检测** | 本地欺诈数据库实时比对，自动识别可疑用户 |
| **白名单** | VIP 用户跳过所有检查，直接转发 |
| **本地管理** | 拉黑/解封/重置验证，回复消息即可操作 |
| **自动消息** | 自定义欢迎消息与自动回复（带 10 分钟冷却） |
| **图形面板** | Inline Keyboard 菜单，配置一键完成 |
| **转发模式** | 私聊 ↔ 话题群组一键切换 |
| **广播推送** | 向所有已验证用户群发消息，支持 HTML，24 小时冷却 |
| **编辑同步** | 用户和管理员编辑消息实时同步 |
| **消息统计** | 自动统计每日消息数和活跃用户数 |
| **零成本运行** | Cloudflare Workers 免费额度长期稳定运行 |

---

## 🚀 快速开始

请直接查看详细部署教程：**[DEPLOY.md](./DEPLOY.md)**。

部署、环境变量、Webhook 激活、Turnstile 配置和话题模式开启步骤都以 `DEPLOY.md` 为准。

---

## 🤖 管理员指令

所有指令建议直接 **回复 (Reply)** 用户转发过来的消息使用，机器人会自动提取目标用户 ID。

### 基础指令

| 指令 | 作用 | 示例 |
|:----:|:----:|:----:|
| 回复消息 | 直接回复内容给用户 | （直接打字发送） |
| `/help` | 显示帮助信息 | `/help` |
| `/menu` | 打开图形化管理面板 | `/menu` |

### 用户管理

| 指令 | 作用 | 示例 |
|:----:|:----:|:----:|
| `/ban` | 封禁用户 | 回复某条消息发送 `/ban` 或 `/ban 123456` |
| `/unban` | 解封用户 | 回复某条消息发送 `/unban` 或 `/unban 123456` |
| `/reset` | 重置用户验证状态 | 回复某条消息发送 `/reset` 或 `/reset 123456` |
| `/trust` | 信任用户（跳过验证） | 回复某条消息发送 `/trust` 或 `/trust 123456` |
| `/untrust` | 取消信任用户 | 回复某条消息发送 `/untrust` 或 `/untrust 123456` |

### 消息设置

| 指令 | 作用 | 示例 |
|:----:|:----:|:----:|
| `/welcome` | 设置欢迎消息 | `/welcome 你好！请先完成验证` |
| `/autoreply` | 设置自动回复 | `/autoreply 客服已收到消息` |
| `/broadcast` | 向所有已验证用户广播消息 | `/broadcast 系统维护通知` |
| `/bcancel` | 取消进行中的广播 | `/bcancel` |

### 系统管理

| 指令 | 作用 | 示例 |
|:----:|:----:|:----:|
| `/cleanup` | 清理失效的话题映射 | `/cleanup` 或 `/cleanup --dry-run` |
| `/cachestats` | 查看缓存统计信息 | `/cachestats` |
| `/clearcache` | 清空所有缓存 | `/clearcache` |

---

## 💬 话题模式 (Forum)

想把每位访客的对话整理到 Telegram 论坛话题？

1. 在 Cloudflare 环境变量中设置 `GROUP_ID`，指向你的论坛群组。
2. 确保机器人在该群里是管理员并拥有「管理话题」权限。
3. 发送 `/menu` → 点击「💬 转发模式」→ 选择「话题转发」。

开启后，机器人会为每位新访客自动创建话题并把消息发到群里，管理员在话题中回复即可回传给访客。

---

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

---

## 🛡️ 安全特性

- **Webhook 安全验证** — 校验 `X-Telegram-Bot-Api-Secret-Token` 头部，防止伪造请求
- **联合封禁** — 接入第三方封禁系统，自动拦截恶意用户
- **欺诈检测** — 本地欺诈数据库，实时比对可疑用户
- **防刷屏保护** — 5 秒内最多 5 条消息，防止消息轰炸
- **人机验证** — Cloudflare Turnstile 验证，有效阻止机器人
- **日志脱敏** — 自动过滤 Token、Secret 等敏感信息

---

## ⚠️ 注意事项

1. **验证延迟**：Cloudflare KV 具有最终一致性，验证通过后可能需要 30 秒才能在全球所有边缘节点生效
2. **白名单优先级**：白名单用户跳过所有检查（包括验证、黑名单、欺诈检测）
3. **消息映射过期**：消息转发映射关系保存 48 小时，超过后无法回复旧消息
4. **广播冷却**：广播功能有 24 小时冷却时间，每次最多发送 500 条消息
5. **编辑限制**：Telegram 限制只能编辑 48 小时内的消息

---

## 🎯 适用场景

- 客服机器人
- 匿名投稿机器人
- 私聊中转机器人
- 反馈收集机器人
- 社群接待机器人

---

## 🛠 技术栈

- JavaScript (ES6+)
- Telegram Bot API
- Cloudflare Workers + KV + Cache API
- Cloudflare Turnstile

---

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

`data/fraud.db` 文件包含已知的欺诈用户 ID 列表，每行一个用户 ID。机器人会自动检测并拦截这些用户。

**自定义欺诈数据库**：
1. 编辑 `data/fraud.db` 文件
2. 每行添加一个用户 ID
3. 提交到 GitHub 后约 1 小时生效（或重启 Worker 立即生效）

---

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

---

## 📜 许可证

本项目基于 [NFD](https://github.com/LloydAsp/nfd) 开发，采用 [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) (GPL-3.0) 开源协议。

作为 GPL-3.0 许可软件的衍生作品，本项目遵循相同的许可证条款。您可以自由使用、修改和分发，但必须遵守 GPL-3.0 的要求，包括：
- 保留版权声明
- 使用相同的许可证（GPL-3.0）发布衍生作品
- 提供源代码

详见 [LICENSE](./LICENSE) 文件。

---

## ⭐ Star History

<a href="https://www.star-history.com/?repos=qianqi32%2FSafeRelay&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=qianqi32/SafeRelay&type=date&theme=dark&legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=qianqi32/SafeRelay&type=date&legend=top-left" />
    <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=qianqi32/SafeRelay&type=date&legend=top-left" />
  </picture>
</a>

---

<div align="center">

**如果这个项目对你有帮助，请给一个 ⭐ Star！**

**Made with ❤️ by [qianqi32](https://github.com/qianqi32/)**

</div>
