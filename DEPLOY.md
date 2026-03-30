# SafeRelay - 部署指南

> 💡 **部署前请仔细阅读完整文档**，确保所有配置项都正确填写。

---

## 前置准备

部署前需要准备以下内容：

| 项目 | 获取方式 | 用途 |
|------|----------|------|
| **Telegram Bot Token** | [@BotFather](https://t.me/BotFather) 创建机器人 | 机器人身份认证 |
| **Admin UID / ADMIN_IDS** | [@userinfobot](https://t.me/userinfobot) 获取你的 User ID | 管理员身份验证。可填写一个 `ENV_ADMIN_UID`，或在 `ADMIN_IDS` 中写入多个 ID（逗号/空格分隔） |
| **Webhook 密钥** | [UUID 生成器](https://www.uuidgenerator.net/) 生成随机 UUID | Webhook 安全验证 |
| **Turnstile Site Key** | Cloudflare Dashboard 创建 | 人机验证 |
| **Turnstile Secret Key** | Cloudflare Dashboard 创建 | 人机验证 |

---

## 步骤 1：配置 Cloudflare Turnstile（必需）

前往 `Cloudflare Dashboard` → `应用程序安全` → `Turnstile`：

1. 点击 **添加小组件** 按钮
2. **小组件名称**：填写 `saferelay`（或其他名称）
3. **主机名管理**：点击 **添加主机名** 按钮
   - 选择 **添加自定义主机名**
   - 填写你的 Workers 域名，例如 `yourname.workers.dev`
   - 点击输入框旁边的 **添加** 按钮
   - 点击下方的 **添加** 按钮确认
4. 点击 **创建** 按钮
5. **保存密钥**：创建成功后会显示
   - **站点密钥 (Site Key)**：复制保存
   - **密钥 (Secret Key)**：复制保存

> ⚠️ **重要**：这两个密钥稍后要填写到代码中！

---

## 步骤 2：创建 KV 命名空间

前往 `Cloudflare Dashboard` → `Storage & Databases` → `Workers KV`：

1. 点击 `Create a Namespace`（创建命名空间）
2. 命名为 `saferelay_kv`（或其他你喜欢的名字）
3. 点击 `Add`（添加）

---

## 步骤 3：创建 Worker

前往 `Cloudflare Dashboard` → `Compute & AI` → `Workers & Pages`：

1. 点击 `Create Application`（创建应用程序）
2. 选择 `HTTP Handler` 模板
3. `Worker Name` 填写 `saferelay`（或其他你喜欢的名字）
4. 点击 `Deploy`（部署）

---

## 步骤 4：编辑代码

1. 进入 `Workers & Pages` → 你的 Worker 名称 → `Edit Code`（编辑代码）
2. 将 [worker.js](./worker.js) 的内容完整复制粘贴进去，覆盖原有代码
3. 代码无需改动，所有密钥都会在下一步通过环境变量注入
4. 点击右上角的 `Deploy`（部署）保存

---

## 步骤 5：绑定 KV

进入 `Workers & Pages` → 你的 Worker 名称 → `Settings`（设置） → `Bindings`（绑定）：

1. 点击 `Add`（添加绑定）
2. 选择 `KV Namespace`（KV 命名空间）
3. `Variable name` **必须填写 `KV`**（必须大写，代码中写死了这个名字）
4. `KV Namespace` 选择刚才创建的 `saferelay_kv`
5. 点击 `Save and deploy`（保存并部署）

---

## 步骤 6：设置环境变量

进入 `Workers & Pages` → 你的 Worker 名称 → `Settings` → `Variables`：

### 必填变量

| 变量 | 类型 | 说明 | 示例 |
|:----:|:----:|:-----|:----:|
| `ENV_BOT_TOKEN` | Secret | Telegram Bot Token | `123456:ABC-DEF...` |
| `ENV_BOT_SECRET` | Secret | 用于 `/registerWebhook` 的 `secret_token`（任意随机串） | `random_string_123` |
| `ENV_ADMIN_UID` / `ADMIN_IDS` | Plain text | 至少填写一个管理员 ID。`ADMIN_IDS` 支持多个 ID，以逗号或空格分隔 | `123456789,987654321` |

### 可选变量

| 变量 | 类型 | 说明 | 示例 |
|:----:|:----:|:-----|:----:|
| `ADMIN_IDS` | Plain text | 多管理员列表；即使已经设置 `ENV_ADMIN_UID` 也建议写在这里 | `111,222,333` |
| `CF_TURNSTILE_SITE_KEY` | Secret | Turnstile 站点密钥（启用网页验证时需要） | `0x4AAAAAA...` |
| `CF_TURNSTILE_SECRET_KEY` | Secret | Turnstile 密钥（启用网页验证时需要） | `0x4AAAAAA...` |
| `WORKERS_AI_ENABLED` | Plain text | 启用 Workers AI 垃圾检测 | `true` |
| `GROUP_ID` | Plain text | 论坛群组 / Topics 模式所需 | `-1001234567890` |
| `TURNSTILE_ALLOWED_HOSTNAMES` | Plain text | Turnstile Hostname 白名单，逗号或空格分隔 | `bot.example.com workers.dev` |
| `TURNSTILE_ACTION` | Plain text | Turnstile Action 校验值 | `tg_verify` |
| `VERIFY_SIGNING_SECRET` | Secret | 自定义 HMAC 密钥（不设置则使用 `ENV_BOT_SECRET`） | `my_sign_secret` |

点击 `Save and deploy`（保存并部署）

---

## 步骤 7：激活 Webhook

部署完成后，在浏览器访问以下 URL 来激活机器人：

```
https://<你的 worker 域名>/registerWebhook
```

---

## 可选：启用话题模式

如果希望管理员在 Telegram 论坛话题里统一处理访客消息：

1. 在 `Workers & Pages → Settings → Variables` 中设置 `GROUP_ID`（论坛群组 ID，如 `-1001234567890`）。
2. 确保机器人在该群组是管理员，并拥有“管理话题”权限。
3. 在 Telegram 中发送 `/menu`，点击「💬 转发模式」，切换为“话题转发”。

启用后，机器人会为每位访客自动创建话题，并把后续消息都发到对应的话题中。管理员在话题里回复即可把消息回传给访客。

示例：
```
https://saferelay.yourname.workers.dev/registerWebhook
```

如果看到 `Ok`，说明部署成功！

发送 `/start` 给你的机器人，确认可以收到机器人回复。

> 💡 **管理员指令**：详细指令说明请查看 [README.md](./README.md#-管理员指令)

---

## （可选）步骤 8：配置 Workers AI

如需启用 AI 智能垃圾消息检测，请完成以下步骤：

### 1. 开通 Workers AI

1. 前往 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 导航到 **Workers & Pages** → **AI**
3. 点击 **Enable Workers AI**
4. 绑定支付方式（Workers AI 有免费额度）

### 2. 确认环境变量

确保已设置环境变量：
```
WORKERS_AI_ENABLED=true
```

### 3. 启用 AI 检测

1. 发送 `/menu` 打开管理面板
2. 点击 **垃圾消息过滤**
3. 点击 **AI 智能检测**
4. 开启 AI 检测并设置阈值（推荐 0.7-0.8）

### 4. 监控 AI 使用量

- 发送 `/spamstats` 查看 AI 检测统计
- 在 Cloudflare Dashboard → Workers → AI 查看使用量
- 免费额度：每小时 100 次调用

> ⚠️ **注意**：Workers AI 为付费服务，但免费额度足够个人使用。如超出免费额度，会产生额外费用。

---

## （可选）步骤 9：配置论坛群组话题

如使用 Telegram 论坛群组（Forum Group），需要配置话题功能：

### 1. 获取群组 ID

1. 将机器人添加到论坛群组
2. 发送 `/start` 给机器人
3. 查看日志或使用 [@RawDataBot](https://t.me/RawDataBot) 获取群组 ID
4. 群组 ID 通常为负数，如 `-1001234567890`

### 2. 设置环境变量

添加环境变量：
```
GROUP_ID=-1001234567890
```

### 3. 测试话题功能

1. 用户发送消息给机器人
2. 机器人应自动在论坛群组创建话题
3. 消息应转发到对应话题

### 4. 清理失效话题

如话题被删除，可使用清理命令：
```
/cleanup
```

---

## ⚠️ 注意事项

### 核心配置
1. **KV 绑定名称**：请确保 KV Namespace 的变量名绑定为 `KV`，否则机器人无法记忆状态。
2. **KV 延迟**：Cloudflare KV 存在短暂的最终一致性延迟（约 1 分钟）。如果你刚解封用户，可能需要等几十秒才会生效。
3. **Webhook 必须激活**：部署完成后必须访问 `/registerWebhook`，否则机器人无法接收消息。

### 功能选项
4. **联合封禁**：使用第三方服务查询，会共享用户 ID，请根据隐私需求决定是否开启。
5. **消息映射过期**：消息转发映射关系保存 48 小时，超过后无法回复旧消息。
6. **Workers AI**：为可选功能，启用后会产生 AI 调用费用（免费额度内免费）。
7. **论坛群组**：仅在使用 Telegram 论坛群组时需要设置 `GROUP_ID`。

### 安全配置
8. **Webhook Secret Token**：建议启用，防止伪造请求。使用 `/webhooksecret` 命令设置。
9. **并发验证锁**：已默认启用，防止并发验证攻击。

---

## ❓ 常见问题

### 部署问题

**Q: 为什么部署后机器人不回复消息？**  
A: 请检查：
1. Webhook 是否已激活（访问 `/registerWebhook`）
2. 环境变量 `ENV_BOT_TOKEN` 是否正确
3. 查看 Cloudflare Worker 的日志排查错误

**Q: 如何查看日志？**  
A: 进入 Cloudflare Dashboard → Workers & Pages → 你的 Worker → Logs

**Q: 如何更新代码？**  
A: 手动复制新版本的 `worker.js` 代码，重新部署：
1. 下载最新版 [worker.js](./worker.js)
2. 进入你的 Worker → `Edit Code`
3. 粘贴新代码（注意保留你的 Turnstile 密钥）
4. 点击 `Deploy`

**Q: 更新代码后需要重新激活 Webhook 吗？**  
A: 不需要，Webhook 只需激活一次。

### Workers AI 相关

**Q: Workers AI 收费吗？**  
A: Workers AI 是付费服务，但提供充足的免费额度。个人使用通常不会超出免费额度。

**Q: AI 检测不生效怎么办？**  
A: 请检查：
1. 是否设置 `WORKERS_AI_ENABLED=true`
2. 是否在管理面板中启用了 AI 检测
3. 查看日志是否有 AI API 调用错误

**Q: 如何调整 AI 检测阈值？**  
A: 发送 `/menu` → 垃圾消息过滤 → AI 智能检测 → 调整阈值（推荐 0.7-0.8）

### 论坛群组相关

**Q: 话题功能不生效怎么办？**  
A: 请检查：
1. 是否设置 `GROUP_ID` 环境变量
2. 群组是否为论坛群组（Forum Group）
3. 机器人是否有创建话题的权限

**Q: 如何清理失效的话题？**  
A: 使用 `/cleanup` 命令清理失效的话题映射

### 性能优化

**Q: 如何查看缓存性能？**  
A: 发送 `/cachestats` 查看缓存统计

**Q: 缓存命中率低怎么办？**  
A: 这是正常现象，L2 缓存会跨实例共享，整体性能仍然优秀。

**Q: 如何清空缓存？**  
A: 发送 `/clearcache` 清空所有缓存
