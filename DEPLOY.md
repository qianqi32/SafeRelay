# SafeRelay - 部署指南

> 💡 **部署前请仔细阅读完整文档**，确保所有配置项都正确填写。

---

## 前置准备

部署前需要准备以下内容：

| 项目                     | 获取方式                                                    | 用途             |
| ------------------------ | ----------------------------------------------------------- | ---------------- |
| **Telegram Bot Token**   | [@BotFather](https://t.me/BotFather) 创建机器人             | 机器人身份认证   |
| **Admin UID**            | [@userinfobot](https://t.me/userinfobot) 获取你的 TG ID     | 管理员身份验证   |
| **Webhook 密钥**         | [UUID 生成器](https://www.uuidgenerator.net/) 生成随机 UUID | Webhook 安全验证 |
| **Turnstile Site Key**   | Cloudflare Dashboard 创建                                   | 人机验证         |
| **Turnstile Secret Key** | Cloudflare Dashboard 创建                                   | 人机验证         |

如果准备使用话题模式，请提前确认：

1. 在 BotFather 中关闭机器人 **Group Privacy**。
2. 管理员群组必须是超级群组并开启 **Topics/话题** 功能。
3. 机器人必须是群管理员，并拥有「管理话题」权限。

---

## 步骤 1：配置 Cloudflare Turnstile（必需）

前往 `Cloudflare左边工具栏` → `应用程序安全` → `Turnstile`：

1. 点击 **添加小组件** 按钮
2. **小组件名称**：填写 `tgbot`（或其他名称）
3. **主机名管理**：点击 **添加主机名** 按钮
   - 选择 **添加自定义主机名**
   - 填写你的 Workers 域名或自己的域名，例如 `tgbot.example.workers.dev` 改成自己的
   - 点击输入框旁边的 **添加** 按钮
   - 点击下方的 **添加** 按钮确认
4. 点击 **创建** 按钮
5. **保存密钥**：创建成功后会显示
   - **站点密钥**：复制保存
   - **密钥**：复制保存

> ⚠️ **重要**：这两个密钥稍后要填写到代码中！

---

## 步骤 2：创建 KV 命名空间

前往 `Cloudflare左边工具栏` → `存储和数据库` → `Workers KV`：

1. 点击右上角  `Create Instance`（创建命名空间）
2. 命名为 `tgbot_kv`（或其他你喜欢的名字）
3. 点击 `创建`（添加）

---

## 方案 A：Wrangler CLI 部署（推荐）

项目已有 [wrangler.toml](./wrangler.toml)，一行命令部署：

```bash
# 1. 登录 Cloudflare
npx wrangler login

# 2. 创建 KV 并部署（会自动提示你绑定）
npx wrangler kv:namespace create KV
# → 复制返回的 ID，粘贴到 wrangler.toml 的 id = "" 中

# 3. 设置密钥
npx wrangler secret put ENV_BOT_TOKEN
npx wrangler secret put ENV_BOT_SECRET
npx wrangler secret put ENV_ADMIN_UID

# 4. 部署
npx wrangler deploy
```

部署完访问 `https://你的worker域名/registerWebhook` 激活。

---

## 方案 B：Dashboard 手动部署

### 步骤 1：创建 Worker

前往 `Cloudflare` → `计算` → `Workers & Pages`：

1. 点击 `创建应用程序` → `从 Hello World! 开始`
2. `Worker Name` 填 `tgbot`，点击 `部署`
3. 复制你的 Worker 域名，例如 `tgbot.example.workers.dev`

### 步骤 2：回填 Turnstile 主机名

回到 `应用程序安全` → `Turnstile`：

1. 找到刚才创建的小组件 → 最右侧 **三个点** → **编辑**
2. 在 **主机名管理** 中添加 Worker 域名
3. 删除之前写的临时主机名，点击 **更新**

> ⚠️ Turnstile 主机名必须和 Worker 域名一致，否则验证页面加载失败

### 步骤 3：编辑代码

1. `Workers & Pages` → 你的 worker → 右上角 `编辑代码`
2. 将 [worker.js](./worker.js) 全部内容粘贴覆盖
3. 点击右上角 `部署`

### 步骤 4：绑定 KV

`Workers & Pages` → 你的 worker → `设置` → `绑定` → `添加绑定+`：

- **变量名称**: `KV`（必须大写，代码写死了这个变量名）
- **KV 命名空间**: 选择刚才创建的 `tgbot_kv`
- 点击 `添加绑定`

### 步骤 5：设置环境变量

`Workers & Pages` → 你的 worker → `设置` → `变量和机密`：

### 必填变量

|       变量       | 类型 | 说明                                                         |                  示例                  |
| :--------------: | :--: | :----------------------------------------------------------- | :------------------------------------: |
| `ENV_BOT_TOKEN`  | 密钥 | Telegram Bot Token                                           |          `123456:ABC-DEF...`           |
| `ENV_BOT_SECRET` | 密钥 | 用于 `/registerWebhook` 的开头网站获取的 `随机UUID`也可自己填写 | `d7ecca95-e45e-41f4-b018-d5cc05486283` |
| `ENV_ADMIN_UID`  | 文本 | 你的TGID 至少填写一个管理员ID。                              |              `123456789`               |

### 建议添加
|           变量            | 类型 | 说明                      |       示例       |
| :-----------------------: | :--: | :------------------------ | :--------------: |
|  `CF_TURNSTILE_SITE_KEY`  | 密钥 | `站点密钥` 刚才复制到那个 |  `0x4AAAAAA...`  |
| `CF_TURNSTILE_SECRET_KEY` | 密钥 | `密钥` 刚才复制到那个     |  `0x4AAAAAA...`  |
|        `GROUP_ID`         | 文本 | 你的群组ID                | `-1001234567890` |

### 可选变量

|             变量              |  类型  | 说明                                                         |             示例              |
| :---------------------------: | :----: | :----------------------------------------------------------- | :---------------------------: |
|          `ADMIN_IDS`          |  文本  | 多管理员 ID 列表，用英文逗号分隔；不能代替必填变量 `ENV_ADMIN_UID` |         `111,222,333`         |
|     `CF_ACCOUNT_ID`      |  密钥  | Cloudflare Account ID（启用 AI 检测时需要）                  |    `abc123...`    |
|      `CF_AI_TOKEN`       |  密钥  | Cloudflare API Token，权限选 Workers AI → Run（启用 AI 检测时需要） | `sk-abc123...` |
| `TURNSTILE_ALLOWED_HOSTNAMES` |  文本  | Turnstile 允许验证的域名白名单，多个域名用英文逗号或空格分隔 | `tgbot.example.workers.dev` |
|      `TURNSTILE_ACTION`       |  文本  | Turnstile 验证动作名称，通常保持默认即可                    |          `tg_verify`          |
|    `VERIFY_SIGNING_SECRET`    |  密钥  | 验证链接签名密钥；不设置时默认使用 `ENV_BOT_SECRET`          |       `my_sign_secret`        |

点击 `Save and deploy`（保存并部署）

---

## 步骤 7：激活 Webhook

部署完成后，在浏览器访问以下 URL 来激活机器人（仅更改前面的域名 ）：

```
https://<你的 worker 域名>/registerWebhook
```
例如： `https://tgbot.example.workers.dev/registerWebhook`

---

## 可选：启用话题模式

如果希望管理员在 Telegram 论坛话题里统一处理访客消息：

1. 在 `Workers & Pages → 设置 → 变量和机密` 中设置 `GROUP_ID`（论坛群组 ID，如 `-1001234567890`）。
2. 确保机器人在该群组是管理员，让拥有“管理话题”权限，并且群组要确保群组开启了话题功能。
3. 在 Telegram 你的刚刚创建的bot中发送 `/menu`，点击「💬 转发模式」，切换为“话题转发”。
4. 其实第7步完成应该会弹窗

启用后，机器人会为每位访客自动创建话题，并把后续消息都发到对应的话题中。管理员在话题里回复即可把消息回传给访客。

发送 `/start` 给你的机器人，确认可以收到机器人回复。

> 💡 **管理员指令**：详细指令说明请查看 [README.md](./README.md#-管理员指令)

---

## 前方的区域请自行探索，现在的功能已经够用了
## （可选）步骤 8：配置 Workers AI

如需启用 AI 智能垃圾消息检测，请完成以下步骤：

### 1. 获取 Cloudflare Account ID

1. 前往 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 `Workers & Pages`，页面右侧即可看到 **Account ID**，点击复制
3. 或者直接看浏览器地址栏：`https://dash.cloudflare.com/<这串就是 Account ID>`

### 2. 创建 API Token

1. 右上角头像 → **My Profile** → **API Tokens**
2. 点击 **Create Token**
3. 找到 **Workers AI** 模版（或点 **Create Custom Token** 手动创建），点击 **使用模板**
4. 如果手动创建，配置权限：
   - Permissions: `Account` → `Workers AI` → `Edit`
   - Account Resources: 选择你的账户
5. 点击 **Continue to summary** → **Create Token**
6. 复制生成的 Token（只显示一次）

### 3. 设置环境变量

添加以下两个**密钥**类型变量：

```
CF_ACCOUNT_ID = 第一步的 Account ID
CF_AI_TOKEN   = 第二步的 API Token
```

### 4. 启用 AI 检测

1. 发送 `/menu` 打开管理面板
2. 点击 **🤖 AI 检测**
3. 点击 **🟢 开启 AI 检测**
4. 可通过 **⚙️ 调整置信度** 设置阈值（推荐 0.7）

### 5. 监控 AI 使用量

- 管理面板 → 🤖 AI 检测 → **📊 查看使用统计**
- 在 [Cloudflare AI Dashboard](https://dash.cloudflare.com/ai/workers-ai) 查看 Workers AI 总用量

> 💡 **免费额度**：Workers AI 每天提供 10,000 Neurons 免费额度（短文本分类每次约消耗 1-2 Neurons），个人使用通常不会超出。

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
6. **Workers AI**：为可选功能，需设置 `CF_ACCOUNT_ID` 和 `CF_AI_TOKEN` 环境变量。使用 Llama 3.2 3B 模型，每天 10,000 Neurons 免费额度。
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
A: Workers AI 每天提供 10,000 Neurons 免费额度，短文本分类每次约消耗 1-2 Neurons，个人使用通常不会超出免费额度。

**Q: AI 检测不生效怎么办？**  
A: 请检查：
1. 是否设置了 `CF_ACCOUNT_ID` 和 `CF_AI_TOKEN` 两个环境变量
2. 是否在管理面板（🤖 AI 检测）中启用了 AI 检测
3. 在 Cloudflare Worker Logs 中搜索 `ai_api_call_failed` 或 `ai_detection_failed` 排查错误

**Q: 如何调整 AI 检测阈值？**  
A: 发送 `/menu` → 🤖 AI 检测 → ⚙️ 调整置信度 → 输入数值（推荐 0.7）

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