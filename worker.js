/**
 * SafeRelay - Telegram 双向机器人
 * 项目地址: https://github.com/qianqi32/SafeRelay
 * 版本: 1.0.2
 * 当前版本可能仍不稳定，如遇到 BUG 请提交至 issues
*/

// Cloudflare Turnstile 配置（需要手动填写）
const CF_TURNSTILE_SITE_KEY = '0x4AAAAAAAXXXXXXXXXXXXXXXXXXXX';  // 替换为你的 Site Key
const CF_TURNSTILE_SECRET_KEY = '0x4AAAAAAAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';  // 替换为你的 Secret Key

// 基础配置（不需要修改，在 KV 中配置）
const TOKEN = ENV_BOT_TOKEN;
const WEBHOOK = '/endpoint';
const SECRET = ENV_BOT_SECRET;
const ADMIN_UID = ENV_ADMIN_UID;

// 验证通过后的有效期 (秒)，默认 7 天
const VERIFICATION_TTL = 60 * 60 * 24 * 7;

// 防刷屏配置
const RATE_LIMIT_WINDOW_MS = 5000; // 5秒窗口
const RATE_LIMIT_MAX_MSG = 5; // 5秒内最多5条消息

// 联合封禁配置
const UNION_BAN_API_URL = "https://verify.wzxabc.eu.org";
const UNION_BAN_CACHE_TTL = 3600 * 24;

// 本地欺诈数据库配置
const FRAUD_DB_URL = 'https://raw.githubusercontent.com/qianqi32/SafeRelay/main/data/fraud.db';
const FRAUD_CACHE_TTL = 3600; // 1小时缓存

// 调用联合封禁 API
async function callUnionBanApi(endpoint, payload) {
    try {
        const baseUrl = UNION_BAN_API_URL.endsWith('/') ? UNION_BAN_API_URL.slice(0, -1) : UNION_BAN_API_URL;
        const resp = await fetch(`${baseUrl}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) {
            console.error(`Union Ban API Error [${endpoint}]: HTTP ${resp.status}`);
            return null;
        }
        return await resp.json();
    } catch (e) {
        console.error(`Union Ban API Network Error [${endpoint}]:`, e);
        return null;
    }
}

// 检查用户是否被联合封禁
async function checkUnionBan(userId) {
    const gbanKey = `gban:${userId}`;

    // 1. 检查内存缓存
    let gbanStatus = memGet(gbanKey);
    if (gbanStatus !== undefined) {
        return gbanStatus === "true";
    }

    // 2. 检查 KV 缓存
    gbanStatus = await KV.get(gbanKey);
    if (gbanStatus !== null) {
        memSet(gbanKey, gbanStatus, 30 * 60 * 1000);
        return gbanStatus === "true";
    }

    // 3. 调用远程 API
    const remoteCheck = await callUnionBanApi('/check_ban', { user_id: String(userId) });
    gbanStatus = (remoteCheck && remoteCheck.banned) ? "true" : "false";

    // 写入 KV 缓存
    await KV.put(gbanKey, gbanStatus, { expirationTtl: UNION_BAN_CACHE_TTL });
    memSet(gbanKey, gbanStatus, 30 * 60 * 1000);

    return gbanStatus === "true";
}

// 检查用户是否在欺诈数据库中
async function checkFraud(userId) {
    const fraudKey = `fraud:${userId}`;

    // 1. 检查内存缓存
    let fraudStatus = memGet(fraudKey);
    if (fraudStatus !== undefined) {
        return fraudStatus === "true";
    }

    // 2. 检查 KV 缓存
    fraudStatus = await KV.get(fraudKey);
    if (fraudStatus !== null) {
        memSet(fraudKey, fraudStatus, FRAUD_CACHE_TTL * 1000);
        return fraudStatus === "true";
    }

    // 3. 获取欺诈数据库
    try {
        const db = await fetch(FRAUD_DB_URL).then(r => r.text());
        const fraudList = db.split('\n').filter(v => v.trim());
        const isFraud = fraudList.includes(userId.toString());

        fraudStatus = isFraud ? "true" : "false";

        // 写入 KV 缓存（1小时）
        await KV.put(fraudKey, fraudStatus, { expirationTtl: FRAUD_CACHE_TTL });
        memSet(fraudKey, fraudStatus, FRAUD_CACHE_TTL * 1000);

        return isFraud;
    } catch (err) {
        console.error('检查欺诈数据库错误:', err);
        return false;
    }
}

// 内存缓存层
const memCache = new Map();
const MEMORY_CACHE_TTL = 30 * 60 * 1000;

function memGet(key) {
    const item = memCache.get(key);
    if (!item) return undefined;
    if (Date.now() > item.expiry) {
        memCache.delete(key);
        return undefined;
    }
    return item.value;
}

function memSet(key, value, ttlMs = MEMORY_CACHE_TTL) {
    memCache.set(key, { value, expiry: Date.now() + ttlMs });
    // 当缓存过大时，清理最旧的 20% 条目
    if (memCache.size > 2000) {
        const entriesToDelete = Math.floor(memCache.size * 0.2);
        const entries = Array.from(memCache.entries());
        // 按过期时间排序，删除最早过期的
        entries.sort((a, b) => a[1].expiry - b[1].expiry);
        for (let i = 0; i < entriesToDelete; i++) {
            memCache.delete(entries[i][0]);
        }
    }
}

function memDelete(key) {
    memCache.delete(key);
}

// 检查用户是否已验证（优先使用内存缓存）
async function isUserVerified(userId) {
    const verifiedKey = 'verified-' + userId;

    // 1. 先检查内存缓存
    const memVerified = memGet(verifiedKey);
    if (memVerified !== undefined) {
        return memVerified === "true";
    }

    // 2. 检查 KV
    const kvVerified = await KV.get(verifiedKey);
    if (kvVerified === 'true') {
        // 更新内存缓存
        memSet(verifiedKey, 'true', 5 * 60 * 1000);
        return true;
    }

    return false;
}

// 获取所有白名单用户
async function getWhitelist() {
    const whitelistData = await KV.get('whitelist-data');
    return whitelistData ? whitelistData.split(',').filter(v => v) : [];
}

// 检查用户是否在白名单中
async function isWhitelisted(userId) {
    const whitelist = await getWhitelist();
    return whitelist.includes(userId);
}

// 添加用户到白名单
async function addToWhitelist(userId) {
    const whitelist = await getWhitelist();
    if (!whitelist.includes(userId)) {
        whitelist.push(userId);
        await KV.put('whitelist-data', whitelist.join(','));
    }
}

// 从白名单移除用户
async function removeFromWhitelist(userId) {
    const whitelist = await getWhitelist();
    const newWhitelist = whitelist.filter(id => id !== userId);
    await KV.put('whitelist-data', newWhitelist.join(','));
}

// 防刷屏限流器
const rateLimitCache = new Map();

function checkRateLimit(userId) {
    const now = Date.now();
    const key = `ratelimit:${userId}`;
    let userData = rateLimitCache.get(key);
    
    if (!userData) {
        userData = { count: 1, firstMessage: now };
        rateLimitCache.set(key, userData);
        return { allowed: true, remaining: RATE_LIMIT_MAX_MSG - 1 };
    }
    
    // 检查是否在时间窗口内
    if (now - userData.firstMessage > RATE_LIMIT_WINDOW_MS) {
        // 重置窗口
        userData.count = 1;
        userData.firstMessage = now;
        return { allowed: true, remaining: RATE_LIMIT_MAX_MSG - 1 };
    }
    
    // 在窗口内，检查次数
    if (userData.count >= RATE_LIMIT_MAX_MSG) {
        const retryAfter = Math.ceil((RATE_LIMIT_WINDOW_MS - (now - userData.firstMessage)) / 1000);
        return { allowed: false, retryAfter };
    }
    
    userData.count++;
    return { allowed: true, remaining: RATE_LIMIT_MAX_MSG - userData.count };
}

// 已验证用户列表管理（新版：同时保存用户ID和昵称）
async function addVerifiedUser(userId, userInfo = null) {
    const key = 'verified_users_list_v2';
    try {
        // 确保用户ID是字符串
        const userIdStr = String(userId);

        const users = await KV.get(key);
        const userMap = users ? new Map(JSON.parse(users)) : new Map();

        // 获取用户昵称
        let userName = userInfo;
        if (!userName) {
            // 尝试从已有数据获取
            const existing = userMap.get(userIdStr);
            if (existing) userName = existing;
        }
        if (!userName) userName = 'Unknown';

        // 只有新用户或昵称变化才更新
        const existing = userMap.get(userIdStr);
        if (!existing || existing !== userName) {
            userMap.set(userIdStr, userName);
            await KV.put(key, JSON.stringify([...userMap]));
        }
    } catch (e) {
        console.error('Failed to add verified user:', e);
    }
}

async function removeVerifiedUser(userId) {
    const key = 'verified_users_list_v2';
    try {
        // 确保用户ID是字符串
        const userIdStr = String(userId);

        const users = await KV.get(key);
        if (!users) return;

        const userMap = new Map(JSON.parse(users));
        if (userMap.has(userIdStr)) {
            userMap.delete(userIdStr);
            await KV.put(key, JSON.stringify([...userMap]));
        }
    } catch (e) {
        console.error('Failed to remove verified user:', e);
    }
}

async function getAllVerifiedUsers() {
    const key = 'verified_users_list_v2';
    try {
        const users = await KV.get(key);
        if (!users) {
            return [];
        }
        // 确保所有key都是字符串
        const parsed = JSON.parse(users);
        const normalizedMap = new Map();
        for (const [k, v] of parsed) {
            normalizedMap.set(String(k), v);
        }
        return [...normalizedMap];
    } catch (e) {
        console.error('Failed to get verified users:', e);
        return [];
    }
}

// 配置管理
const CONFIG_KEYS = {
    WELCOME_MSG: 'config:welcome_msg',
    AUTO_REPLY_MSG: 'config:auto_reply_msg',
    VERIFY_TTL: 'config:verify_ttl',
    UNION_BAN: 'config:union_ban'
};

async function getConfig(key, defaultValue = null) {
    const cacheKey = `cfg:${key}`;
    let value = memGet(cacheKey);
    if (value !== undefined) return value;

    value = await KV.get(key);
    if (value !== null) {
        memSet(cacheKey, value);
    }
    return value !== null ? value : defaultValue;
}

async function setConfig(key, value) {
    await KV.put(key, value);
    memSet(`cfg:${key}`, value);
}

// 错误上报
async function reportError(error, context = "") {
    try {
        if (!ADMIN_UID || !TOKEN) return;
        const errorText = `🚨 <b>SafeRelay 错误报告</b>\n\n<b>上下文:</b> ${context}\n<b>错误:</b> ${error.message}\n<b>时间:</b> ${new Date().toISOString()}`;
        await sendMessage({
            chat_id: ADMIN_UID,
            text: errorText,
            parse_mode: 'HTML'
        });
    } catch (e) {
        console.error('Failed to report error:', e);
    }
}

// 广播功能 - 获取所有已验证用户
async function getVerifiedUsers() {
    // 使用已验证用户列表
    return await getAllVerifiedUsers();
}

// 分批广播辅助函数（参考 RelayGo 实现）
async function sendBroadcastBatch(broadcastMsg, offset, batchSize) {
    const users = await getVerifiedUsers();
    const total = users.length;
    const batch = users.slice(offset, offset + batchSize);
    
    let sent = 0, failed = 0, skipped = 0;
    const startTime = Date.now();
    const maxDuration = 25000; // 25秒超时
    let timedOut = false;
    
    for (const userId of batch) {
        // 超时检查
        if (Date.now() - startTime > maxDuration) {
            timedOut = true;
            break;
        }
        
        // 检查用户是否被封禁
        const isBlocked = await KV.get('blocked-' + userId);
        if (isBlocked) {
            skipped++;
            continue;
        }
        
        try {
            const result = await sendMessage({
                chat_id: userId,
                text: broadcastMsg,
                parse_mode: 'HTML'
            });
            if (result.ok) sent++;
            else failed++;
        } catch (e) {
            failed++;
        }
        
        // 每25条消息暂停1秒，避免触发限制
        if ((sent + failed) % 25 === 0) {
            await new Promise(r => setTimeout(r, 1000));
        }
    }
    
    const processed = offset + sent + skipped;
    const hasMore = processed < total && !timedOut;
    
    return {
        sent: offset + sent,
        failed,
        skipped,
        total,
        hasMore,
        nextOffset: processed,
        timedOut
    };
}

// 统计功能
async function incrementMessageCount() {
    const today = new Date().toISOString().split('T')[0];
    const dailyKey = `stats:messages:${today}`;
    const totalKey = 'stats:messages:total';
    
    try {
        const dailyCount = await KV.get(dailyKey);
        const totalCount = await KV.get(totalKey);
        
        await KV.put(dailyKey, String(parseInt(dailyCount || '0') + 1), { expirationTtl: 86400 * 30 });
        await KV.put(totalKey, String(parseInt(totalCount || '0') + 1));
    } catch (e) {
        console.error('Failed to increment message count:', e);
    }
}

async function recordActiveUser(userId) {
    const today = new Date().toISOString().split('T')[0];
    const key = `stats:active_users:${today}`;
    
    try {
        const users = await KV.get(key);
        const userSet = users ? JSON.parse(users) : [];
        
        if (!userSet.includes(userId)) {
            userSet.push(userId);
            await KV.put(key, JSON.stringify(userSet), { expirationTtl: 86400 * 7 });
        }
    } catch (e) {
        console.error('Failed to record active user:', e);
    }
}

async function getStats() {
    const today = new Date().toISOString().split('T')[0];
    
    try {
        const totalMessages = await KV.get('stats:messages:total') || '0';
        const todayMessages = await KV.get(`stats:messages:${today}`) || '0';
        
        const activeUsers = await KV.get(`stats:active_users:${today}`);
        const todayActiveCount = activeUsers ? JSON.parse(activeUsers).length : 0;
        
        return {
            totalMessages: parseInt(totalMessages),
            todayMessages: parseInt(todayMessages),
            todayActiveUsers: todayActiveCount
        };
    } catch (e) {
        console.error('Failed to get stats:', e);
        return {
            totalMessages: 0,
            todayMessages: 0,
            todayActiveUsers: 0
        };
    }
}

// 媒体组处理
const mediaGroupBuffers = new Map();
const MEDIA_GROUP_WAIT_MS = 300;
const MEDIA_GROUP_MAX_WAIT_MS = 3000;

async function handleMediaGroup(msg, handler) {
    if (!msg.media_group_id) {
        return handler([msg]);
    }

    const groupKey = msg.media_group_id;
    let buffer = mediaGroupBuffers.get(groupKey);
    const isFirst = !buffer;

    if (isFirst) {
        buffer = { messages: [], handler, lastUpdate: 0 };
        mediaGroupBuffers.set(groupKey, buffer);
    }

    buffer.messages.push(msg);
    buffer.lastUpdate = Date.now();

    if (isFirst) {
        const maxWait = Date.now() + MEDIA_GROUP_MAX_WAIT_MS;
        while (Date.now() < maxWait) {
            await new Promise(r => setTimeout(r, MEDIA_GROUP_WAIT_MS));
            if (Date.now() - buffer.lastUpdate >= MEDIA_GROUP_WAIT_MS) break;
        }
        mediaGroupBuffers.delete(groupKey);
        buffer.messages.sort((a, b) => a.message_id - b.message_id);
        return buffer.handler(buffer.messages);
    }
}

// =================================================================
//                      核心功能
// =================================================================

function apiUrl(methodName, params = null) {
  let query = '';
  if (params) {
    query = '?' + new URLSearchParams(params).toString();
  }
  return `https://api.telegram.org/bot${TOKEN}/${methodName}${query}`;
}

function requestTelegram(methodName, body, params = null) {
  return fetch(apiUrl(methodName, params), {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify(body)
  }).then(r => r.json());
}

function sendMessage(msg = {}) {
  return requestTelegram('sendMessage', msg);
}

function copyMessage(msg = {}) {
  return requestTelegram('copyMessage', msg);
}

function forwardMessage(msg) {
  return requestTelegram('forwardMessage', msg);
}

// 设置 Telegram 命令列表
async function setBotCommands() {
  const adminCommands = [
    { command: 'help', description: '显示帮助信息' },
    { command: 'menu', description: '打开图形管理菜单' },
    { command: 'bcancel', description: '取消进行中的广播' },
    { command: 'listwhite', description: '列出所有白名单用户' },
    { command: 'welcome', description: '设置欢迎消息' },
    { command: 'autoreply', description: '设置自动回复消息' }
  ];

  try {
    // 为管理员设置命令列表
    await requestTelegram('setMyCommands', {
      commands: adminCommands,
      scope: { type: 'chat', chat_id: ADMIN_UID }
    });
    console.log('✅ 管理员命令列表已设置');
  } catch (e) {
    console.error('设置命令列表失败:', e);
  }
}

addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.pathname === WEBHOOK) {
    event.respondWith(handleWebhook(event, url));
  } else if (url.pathname === '/registerWebhook') {
    event.respondWith(registerWebhook(event, url, WEBHOOK, SECRET));
  } else if (url.pathname === '/unRegisterWebhook') {
    event.respondWith(unRegisterWebhook(event));
  } else if (url.pathname === '/verify') {
    event.respondWith(handleVerifyPage(event.request));
  } else if (url.pathname === '/verify-callback') {
    event.respondWith(handleVerifyCallback(event.request));
  } else {
    event.respondWith(new Response('No handler for this request'));
  }
});

async function handleWebhook(event, url) {
  if (event.request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== SECRET) {
    return new Response('Unauthorized', { status: 403 });
  }

  const update = await event.request.json();
  event.waitUntil(onUpdate(update, url.origin));
  return new Response('Ok');
}

async function onUpdate(update, origin) {
  if ('callback_query' in update) {
    // 处理回调查询（管理面板按钮）
    if (String(update.callback_query.from.id) === ADMIN_UID) {
      return handleAdminCallback(update.callback_query);
    }
  } else if ('message' in update) {
    await onMessage(update.message, origin);
  } else if ('edited_message' in update) {
    await onEditedMessage(update.edited_message, origin);
  }
}

async function onMessage(message, origin) {
  const chatId = message.chat.id.toString();

  // 1. 如果是管理员发消息
  if (chatId === ADMIN_UID) {
    return handleAdminMessage(message);
  }

  // 2. 如果是访客 (普通用户)
  else {
    const text = (message.text || '').trim();

    // 0. 检查白名单（白名单用户跳过所有检查）
    const whitelisted = await isWhitelisted(chatId);
    if (whitelisted) {
      // 白名单用户处理 /start 或直接转发
      if (text === '/start') {
        return sendMessage({
          chat_id: chatId,
          text: '👋 欢迎使用 SafeRelay！\n\n您已在白名单中，可以直接发送消息给管理员。'
        });
      }
      return handleGuestMessage(message);
    }

    // 处理 /start 命令
    if (text === '/start') {
      // 检查是否已验证
      const isVerified = await isUserVerified(chatId);
      if (isVerified) {
        return sendMessage({
          chat_id: chatId,
          text: '👋 欢迎使用 SafeRelay！\n\n您已通过验证，可以直接发送消息给管理员。'
        });
      } else {
        // 未验证，进入验证流程
        return handleVerification(message, chatId, origin);
      }
    }

    // 0. 检查联合封禁（如果开启）
    const unionBanEnabled = await getConfig(CONFIG_KEYS.UNION_BAN, '0');
    if (unionBanEnabled === '1' || unionBanEnabled === 'true') {
      const isUnionBanned = await checkUnionBan(chatId);
      if (isUnionBanned) {
        return sendMessage({
          chat_id: chatId,
          text: '🚫 <b>您已被联合封禁。</b>\n\n您的账号因违反服务条款被全局封禁。如有疑问，请联系管理员。',
          parse_mode: 'HTML'
        });
      }
    }

    // 1. 检查欺诈数据库
    const isFraud = await checkFraud(chatId);
    if (isFraud) {
      // 通知管理员
      await sendMessage({
        chat_id: ADMIN_UID,
        text: `🚨 <b>检测到欺诈用户</b>\n\nUID: <code>${chatId}</code>\n该用户出现在欺诈数据库中，已自动拦截。`,
        parse_mode: 'HTML'
      });
      return sendMessage({
        chat_id: chatId,
        text: '🚫 <b>服务不可用</b>\n\n您的账号存在异常，无法使用本服务。',
        parse_mode: 'HTML'
      });
    }

    // 2. 检查本地黑名单（直接读取KV，避免缓存不一致）
    const isBlocked = await KV.get('blocked-' + chatId);
    if (isBlocked) {
      // 被拉黑了，回复提示
      return sendMessage({
        chat_id: chatId,
        text: '🚫 您已被管理员拉黑，无法发送消息。'
      });
    }

    // 3. 检查是否已通过验证（优先使用内存缓存）
    const isVerified = await isUserVerified(chatId);

    if (isVerified) {
      // 4. 检查防刷屏限制
      const rateLimit = checkRateLimit(chatId);
      if (!rateLimit.allowed) {
        return sendMessage({
          chat_id: chatId,
          text: `⚠️ 发送过于频繁，请等待 ${rateLimit.retryAfter} 秒后再试。`
        });
      }
      
      // 已验证，发送自动回复（如果设置了）
      const autoReplyMsg = await getConfig(CONFIG_KEYS.AUTO_REPLY_MSG);
      if (autoReplyMsg) {
        // 检查自动回复冷却时间（10分钟）
        const autoReplyKey = `autoreply:${chatId}`;
        const lastReply = await KV.get(autoReplyKey);
        
        if (!lastReply) {
          await sendMessage({
            chat_id: chatId,
            text: autoReplyMsg
          });
          // 记录发送时间，10分钟后过期
          await KV.put(autoReplyKey, '1', { expirationTtl: 600 });
        }
      }
      // 正常转发给管理员
      return handleGuestMessage(message);
    } else {
      // 未验证，进入验证流程
      return handleVerification(message, chatId, origin);
    }
  }
}

// 处理编辑后的消息
async function onEditedMessage(message, origin) {
  const chatId = message.chat.id.toString();

  // 1. 如果是管理员发消息（编辑回复）
  if (chatId === ADMIN_UID) {
    return handleAdminEditedMessage(message);
  }

  // 2. 如果是访客 (普通用户) 编辑消息
  else {
    // 0. 检查白名单（白名单用户跳过所有检查）
    const whitelisted = await isWhitelisted(chatId);
    if (whitelisted) {
      // 白名单用户直接处理编辑
      return handleGuestEditedMessage(message);
    }

    // 1. 检查黑名单
    const isBlocked = await KV.get('blocked-' + chatId);
    if (isBlocked) {
      // 被拉黑了，忽略编辑
      return;
    }

    // 2. 检查是否已通过验证（优先使用内存缓存）
    const isVerified = await isUserVerified(chatId);

    if (isVerified) {
      // 已验证，转发编辑后的消息
      return handleGuestEditedMessage(message);
    } else {
      // 未验证，忽略编辑
      return;
    }
  }
}

// 辅助函数：尝试从回复或参数中获取目标 ID
async function getTargetId(message, commandName) {
  const text = (message.text || '').trim();
  const args = text.split(/\s+/);
  const reply = message.reply_to_message;

  // 优先 1：从回复的消息中提取
  if (reply && (reply.forward_from || reply.forward_sender_name)) {
    const guestChatId = await KV.get('msg-map-' + reply.message_id);
    if (guestChatId) return guestChatId;
  }

  // 优先 2：从指令参数中提取 (例如 /unblock 123456)
  if (args.length > 1) {
    const potentialId = args[1];
    // 简单的数字校验
    if (/^\d+$/.test(potentialId)) {
      return potentialId;
    }
  }

  return null;
}

// 获取已验证用户列表（支持分页）
async function getVerifiedUsers(page = 1, pageSize = 10) {
  // 获取所有已验证用户（会自动处理新旧版本迁移）
  const allUsers = await getAllVerifiedUsers();

  if (!allUsers || allUsers.length === 0) {
    return { users: [], total: 0, totalPages: 0 };
  }

  try {
    const total = allUsers.length;
    const totalPages = Math.ceil(total / pageSize);

    // 确保页码有效
    page = Math.max(1, Math.min(page, totalPages || 1));

    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    const users = allUsers.slice(start, end);

    // 获取每个用户的详细信息
    const userDetails = [];
    for (const [userId, userName] of users) {
      const blocked = await KV.get('blocked-' + userId);
      const whitelisted = await isWhitelisted(userId);
      userDetails.push({
        id: userId,
        name: userName || 'Unknown',
        blocked: blocked === 'true',
        whitelisted: whitelisted
      });
    }

    return {
      users: userDetails,
      total,
      page,
      totalPages,
      pageSize
    };
  } catch (e) {
    console.error('获取用户列表错误:', e);
    return { users: [], total: 0, totalPages: 0 };
  }
}

// 生成主菜单
async function generateMainMenu() {
  const welcomeMsg = await getConfig(CONFIG_KEYS.WELCOME_MSG);
  const autoReplyMsg = await getConfig(CONFIG_KEYS.AUTO_REPLY_MSG);
  const unionBanEnabled = await getConfig(CONFIG_KEYS.UNION_BAN, '0');
  
  const welcomeStatus = welcomeMsg ? '🟢' : '⚪️';
  const autoReplyStatus = autoReplyMsg ? '🟢' : '⚪️';
  const unionBanStatus = (unionBanEnabled === '1' || unionBanEnabled === 'true') ? '🟢' : '🔴';

  const text = `🛠 <b>SafeRelay 管理面板</b>

📊 <b>当前配置:</b>
🔸 联合封禁 ${unionBanStatus}
🔸 欢迎消息 ${welcomeStatus}
🔸 自动回复 ${autoReplyStatus}

👇 点击下方按钮进入设置`;

  const keyboard = {
    inline_keyboard: [
      [{ text: '🌐 联合封禁', callback_data: 'submenu_union' }, { text: '📊 统计信息', callback_data: 'submenu_stats' }],
      [{ text: '👋 欢迎消息', callback_data: 'submenu_welcome' }, { text: '🤖 自动回复', callback_data: 'submenu_autoreply' }],
      [{ text: '👥 用户管理', callback_data: 'submenu_users' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成联合封禁子菜单
async function generateUnionBanSubmenu() {
  const unionBanEnabled = await getConfig(CONFIG_KEYS.UNION_BAN, '0');
  const isEnabled = unionBanEnabled === '1' || unionBanEnabled === 'true';

  const text = `🌐 <b>联合封禁设置</b>

当前状态: ${isEnabled ? '🟢 已开启' : '🔴 已关闭'}

联合封禁可以自动拦截已被其他服务标记为恶意的用户。

👇 点击下方按钮切换状态`;

  const keyboard = {
    inline_keyboard: [
      [{ text: isEnabled ? '🔴 关闭联合封禁' : '🟢 开启联合封禁', callback_data: 'toggle_union' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成欢迎消息子菜单
async function generateWelcomeSubmenu() {
  const current = await getConfig(CONFIG_KEYS.WELCOME_MSG);
  const currentText = current ? escapeHtml(current) : "(未设置，使用默认消息)";

  const text = `👋 <b>欢迎消息设置</b>

📄 <b>当前内容:</b>
<pre>${currentText}</pre>

💡 <b>使用方法:</b>
• 发送 <code>/welcome 消息内容</code> 设置新消息
• 发送 <code>/welcome delete</code> 删除并使用默认

用户首次联系机器人时会看到此消息。`;

  const keyboard = {
    inline_keyboard: [
      [{ text: '🔄 刷新状态', callback_data: 'refresh_welcome' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成自动回复子菜单
async function generateAutoreplySubmenu() {
  const current = await getConfig(CONFIG_KEYS.AUTO_REPLY_MSG);
  const currentText = current ? escapeHtml(current) : "(已关闭)";

  const text = `🤖 <b>自动回复设置</b>

📄 <b>当前内容:</b>
<pre>${currentText}</pre>

💡 <b>使用方法:</b>
• 发送 <code>/autoreply 消息内容</code> 设置自动回复
• 发送 <code>/autoreply off</code> 关闭自动回复

已验证用户发送 /start 时会收到此回复。`;

  const keyboard = {
    inline_keyboard: [
      [{ text: '🔄 刷新状态', callback_data: 'refresh_autoreply' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成统计信息子菜单
async function generateStatsSubmenu() {
  const stats = await getStats();
  const today = new Date().toISOString().split('T')[0];

  const text = `📊 <b>统计信息</b>

📅 <b>今日数据 (${today})</b>
• 消息数: ${stats.todayMessages}
• 活跃用户: ${stats.todayActiveUsers}

📈 <b>累计数据</b>
• 总消息数: ${stats.totalMessages}

💡 数据每小时自动更新`;

  const keyboard = {
    inline_keyboard: [
      [{ text: '🔄 刷新数据', callback_data: 'refresh_stats' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成用户管理子菜单
async function generateUsersSubmenu(page = 1) {
  const result = await getVerifiedUsers(page, 10);

  if (result.total === 0) {
    const text = `👥 <b>用户管理</b>

暂无已验证用户。

💡 用户使用 /start 并通过验证后会出现在这里。`;

    const keyboard = {
      inline_keyboard: [
        [{ text: '🔄 刷新', callback_data: 'refresh_users:1' }],
        [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
      ]
    };

    return { text, reply_markup: keyboard };
  }

  let userList = '';
  for (const user of result.users) {
    const status = user.blocked ? '🚫' : (user.whitelisted ? '⭐' : '✅');
    const name = user.name !== 'Unknown' ? ` (${escapeHtml(user.name)})` : '';
    userList += `${status} <code>${user.id}</code>${name}\n`;
  }

  const text = `👥 <b>用户管理</b>

📊 <b>统计:</b> 共 ${result.total} 位用户 | 第 ${result.page}/${result.totalPages} 页

<b>用户列表:</b>
${userList}
<b>图例:</b> ✅正常 ⭐白名单 🚫已拉黑

💡 <b>操作提示:</b>
• 点击用户ID可复制
• 使用指令管理用户:
  /block, /unblock, /clear_ver
  /addwhite, /removewhite`;

  // 构建分页按钮
  const paginationButtons = [];
  if (result.page > 1) {
    paginationButtons.push({ text: '◀️ 上一页', callback_data: `users_page:${result.page - 1}` });
  }
  paginationButtons.push({ text: '🔄 刷新', callback_data: `refresh_users:${result.page}` });
  if (result.page < result.totalPages) {
    paginationButtons.push({ text: '▶️ 下一页', callback_data: `users_page:${result.page + 1}` });
  }

  const keyboard = {
    inline_keyboard: [
      paginationButtons,
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 处理管理员回调
async function handleAdminCallback(callbackQuery) {
  const data = callbackQuery.data;
  const chatId = callbackQuery.message.chat.id;
  const messageId = callbackQuery.message.message_id;

  // 返回主菜单
  if (data === 'back_to_main') {
    const menu = await generateMainMenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  // 主菜单 - 进入子菜单
  if (data === 'submenu_union') {
    const menu = await generateUnionBanSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  if (data === 'submenu_welcome') {
    const menu = await generateWelcomeSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  if (data === 'submenu_autoreply') {
    const menu = await generateAutoreplySubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  if (data === 'submenu_stats') {
    const menu = await generateStatsSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  // 用户管理 - 进入子菜单
  if (data === 'submenu_users') {
    const menu = await generateUsersSubmenu(1);
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  // 用户管理 - 翻页
  if (data.startsWith('users_page:')) {
    const page = parseInt(data.split(':')[1]) || 1;
    const menu = await generateUsersSubmenu(page);
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: `第 ${page} 页` });
  }

  // 用户管理 - 刷新
  if (data.startsWith('refresh_users:')) {
    const page = parseInt(data.split(':')[1]) || 1;
    const menu = await generateUsersSubmenu(page);
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '已刷新' });
  }

  // 联合封禁 - 切换状态
  if (data === 'toggle_union') {
    const currentVal = await getConfig(CONFIG_KEYS.UNION_BAN, '0');
    const isEnabled = currentVal === '1' || currentVal === 'true';
    const newVal = isEnabled ? '0' : '1';
    await setConfig(CONFIG_KEYS.UNION_BAN, newVal);
    
    const menu = await generateUnionBanSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { 
      callback_query_id: callbackQuery.id,
      text: isEnabled ? '联合封禁已关闭' : '联合封禁已开启'
    });
  }

  // 刷新子菜单
  if (data === 'refresh_welcome') {
    const menu = await generateWelcomeSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '已刷新' });
  }

  if (data === 'refresh_autoreply') {
    const menu = await generateAutoreplySubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '已刷新' });
  }

  if (data === 'refresh_stats') {
    const menu = await generateStatsSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '已刷新' });
  }

  // 广播控制按钮
  if (data.startsWith('bcontinue:')) {
    const offset = parseInt(data.split(':')[1]) || 0;
    const broadcastMsg = await KV.get(`broadcast_msg:${ADMIN_UID}`);

    if (!broadcastMsg) {
      await requestTelegram('editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text: '❌ 广播消息已过期或被取消',
        parse_mode: 'HTML'
      });
      return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '广播已过期' });
    }

    // 先回复按钮，避免超时
    await requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '正在发送...' });

    const result = await sendBroadcastBatch(broadcastMsg, offset, 500);
    const statusIcon = result.timedOut ? '⚠️' : '✅';
    const statusText = result.timedOut ? '部分完成（超时）' : '完成';

    // 构建按钮
    const inlineKeyboard = [];
    if (result.hasMore) {
      inlineKeyboard.push([{ text: '▶️ 继续发送', callback_data: `bcontinue:${result.nextOffset}` }]);
    }
    inlineKeyboard.push([{ text: '❌ 取消广播', callback_data: 'bcancel' }]);

    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: `${statusIcon} <b>广播${statusText}</b>\n\n✅ 已发送：${result.sent}/${result.total}\n❌ 失败：${result.failed}${result.skipped > 0 ? `\n⏭️ 跳过（封禁）：${result.skipped}` : ''}`,
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: inlineKeyboard }
    });
    return;
  }

  if (data === 'bcancel') {
    await KV.delete(`broadcast_msg:${ADMIN_UID}`);
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: '✅ 已取消广播',
      parse_mode: 'HTML'
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '已取消' });
  }
}

// HTML 转义
function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return String(unsafe || '');
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// 处理管理员消息
async function handleAdminMessage(message) {
  const text = (message.text || '').trim();
  const reply = message.reply_to_message;

  // --- 管理指令区域 ---

  // 指令：/help - 显示帮助信息
  if (text === '/help') {
    return sendMessage({
      chat_id: ADMIN_UID,
      text: '🤖 <b>SafeRelay 管理面板</b>\n\n' +
            '<b>常用指令：</b>\n' +
            '/menu - 打开图形菜单\n' +
            '/help - 显示此帮助信息\n' +
            '/broadcast - 广播消息（24h冷却）\n' +
            '/bcancel - 取消广播\n\n' +
            '<b>用户管理（回复消息或指定ID）：</b>\n' +
            '/block - 拉黑用户\n' +
            '/unblock - 解封用户\n' +
            '/clear_ver - 重置验证\n' +
            '/addwhite - 添加白名单\n' +
            '/removewhite - 移除白名单\n' +
            '/checkwhite - 检查白名单\n' +
            '/listwhite - 白名单列表\n\n' +
            '<b>消息设置：</b>\n' +
            '/welcome - 设置欢迎消息\n' +
            '/autoreply - 设置自动回复\n\n' +
            '<b>快捷操作：</b> 直接回复用户消息即可转发',
      parse_mode: 'HTML'
    });
  }

  // 指令：/menu - 显示管理菜单
  if (text === '/menu') {
    const menu = await generateMainMenu();
    return sendMessage({
      chat_id: ADMIN_UID,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
  }

  // 指令：/welcome - 设置欢迎消息
  if (text.startsWith('/welcome')) {
    const content = text.slice(8).trim();
    if (!content || content === 'delete') {
      await setConfig(CONFIG_KEYS.WELCOME_MSG, '');
      return sendMessage({
        chat_id: ADMIN_UID,
        text: '✅ 欢迎消息已删除（恢复默认）。'
      });
    }
    await setConfig(CONFIG_KEYS.WELCOME_MSG, content);
    return sendMessage({
      chat_id: ADMIN_UID,
      text: '✅ 欢迎消息已设置。'
    });
  }

  // 指令：/autoreply - 设置自动回复
  if (text.startsWith('/autoreply')) {
    const content = text.slice(10).trim();
    if (!content || content === 'off') {
      await setConfig(CONFIG_KEYS.AUTO_REPLY_MSG, '');
      return sendMessage({
        chat_id: ADMIN_UID,
        text: '✅ 自动回复已关闭。'
      });
    }
    await setConfig(CONFIG_KEYS.AUTO_REPLY_MSG, content);
    return sendMessage({
      chat_id: ADMIN_UID,
      text: '✅ 自动回复已设置。'
    });
  }

  // 指令：/block (需回复用户消息)
  if (text === '/block') {
    if (reply && (reply.forward_from || reply.forward_sender_name)) {
      const guestChatId = await KV.get('msg-map-' + reply.message_id);
      if (guestChatId) {
        await KV.put('blocked-' + guestChatId, 'true'); // 永久拉黑
        memDelete('blocked-' + guestChatId); // 清除缓存
        await removeVerifiedUser(guestChatId); // 从已验证列表移除
        return sendMessage({ chat_id: ADMIN_UID, text: `🚫 用户 ${guestChatId} 已被拉黑。` });
      } else {
        return sendMessage({ chat_id: ADMIN_UID, text: '⚠️ 无法获取用户ID，可能是旧消息。' });
      }
    } else {
      return sendMessage({ chat_id: ADMIN_UID, text: '⚠️ 请回复一条用户转发的消息来拉黑。' });
    }
  }

  // 指令：/unblock [ID] (支持回复或手输)
  if (text.startsWith('/unblock')) {
    const targetId = await getTargetId(message, '/unblock');
    if (targetId) {
      await KV.delete('blocked-' + targetId);
      memDelete('blocked-' + targetId); // 清除缓存
      return sendMessage({ chat_id: ADMIN_UID, text: `✅ 用户 ${targetId} 已解封。` });
    } else {
      return sendMessage({ chat_id: ADMIN_UID, text: '⚠️ 格式错误。\n请回复用户消息发送 /unblock\n或发送 /unblock 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/clear_ver [ID] (支持回复或手输)
  if (text.startsWith('/clear_ver')) {
    const targetId = await getTargetId(message, '/clear_ver');
    if (targetId) {
      // 检查用户是否在白名单中
      const isWhite = await isWhitelisted(targetId);
      if (isWhite) {
        return sendMessage({ 
          chat_id: ADMIN_UID, 
          text: `⚠️ 用户 ${targetId} 在白名单中，无需验证即可发送消息。\n\n如需限制该用户，请先使用 /removewhite ${targetId} 移除白名单。` 
        });
      }
      
      await KV.delete('verified-' + targetId);
      memDelete('verified-' + targetId); // 清除缓存
      await removeVerifiedUser(targetId); // 从已验证列表移除
      return sendMessage({ chat_id: ADMIN_UID, text: `🔄 用户 ${targetId} 验证状态已重置。` });
    } else {
      return sendMessage({ chat_id: ADMIN_UID, text: '⚠️ 格式错误。\n请回复用户消息发送 /clear_ver\n或发送 /clear_ver 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/broadcast - 广播消息
  if (text === '/broadcast' || text.startsWith('/broadcast ')) {
    const broadcastMsg = text === '/broadcast' ? '' : text.slice(10).trim();
    if (!broadcastMsg) {
      return sendMessage({
        chat_id: ADMIN_UID,
        text: '⚠️ 格式错误。\n用法：/broadcast 消息内容\n\n支持 HTML 格式：\n<b>粗体</b> <i>斜体</i> <code>代码</code>'
      });
    }

    // 检查24小时冷却
    const lastBroadcast = await KV.get(`broadcast_cooldown:${ADMIN_UID}`);
    if (lastBroadcast) {
      const lastTime = parseInt(lastBroadcast);
      const now = Date.now();
      const cooldownMs = 24 * 60 * 60 * 1000; // 24小时
      const remainingMs = cooldownMs - (now - lastTime);
      
      if (remainingMs > 0) {
        const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));
        return sendMessage({
          chat_id: ADMIN_UID,
          text: `⏳ 广播冷却中，请 ${remainingHours} 小时后再试。`
        });
      }
    }

    // 保存消息到 KV（24小时过期）
    await KV.put(`broadcast_msg:${ADMIN_UID}`, broadcastMsg, { expirationTtl: 86400 });
    // 记录广播时间
    await KV.put(`broadcast_cooldown:${ADMIN_UID}`, Date.now().toString(), { expirationTtl: 86400 });

    // 发送第一批（500人）
    const result = await sendBroadcastBatch(broadcastMsg, 0, 500);
    const statusIcon = result.timedOut ? '⚠️' : '✅';
    const statusText = result.timedOut ? '部分完成（超时）' : '完成';

    // 构建按钮
    const inlineKeyboard = [];
    if (result.hasMore) {
      inlineKeyboard.push([{ text: '▶️ 继续发送', callback_data: `bcontinue:${result.nextOffset}` }]);
    }
    inlineKeyboard.push([{ text: '❌ 取消广播', callback_data: 'bcancel' }]);

    return sendMessage({
      chat_id: ADMIN_UID,
      text: `${statusIcon} <b>广播${statusText}</b>\n\n✅ 已发送：${result.sent}/${result.total}\n❌ 失败：${result.failed}${result.skipped > 0 ? `\n⏭️ 跳过（封禁）：${result.skipped}` : ''}`,
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: inlineKeyboard }
    });
  }

  // 指令：/addwhite [ID] - 添加白名单
  if (text.startsWith('/addwhite')) {
    const targetId = await getTargetId(message, '/addwhite');
    if (targetId) {
      await addToWhitelist(targetId);
      return sendMessage({ chat_id: ADMIN_UID, text: `✅ 用户 ${targetId} 已添加到白名单。` });
    } else {
      return sendMessage({ chat_id: ADMIN_UID, text: '⚠️ 格式错误。\n请回复用户消息发送 /addwhite\n或发送 /addwhite 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/removewhite [ID] - 移除白名单
  if (text.startsWith('/removewhite')) {
    const targetId = await getTargetId(message, '/removewhite');
    if (targetId) {
      await removeFromWhitelist(targetId);
      return sendMessage({ chat_id: ADMIN_UID, text: `✅ 用户 ${targetId} 已从白名单移除。` });
    } else {
      return sendMessage({ chat_id: ADMIN_UID, text: '⚠️ 格式错误。\n请回复用户消息发送 /removewhite\n或发送 /removewhite 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/checkwhite [ID] - 检查白名单状态
  if (text.startsWith('/checkwhite')) {
    const targetId = await getTargetId(message, '/checkwhite');
    if (targetId) {
      const isWhite = await isWhitelisted(targetId);
      return sendMessage({ chat_id: ADMIN_UID, text: `UID: ${targetId} ${isWhite ? '✅ 在白名单中' : '❌ 不在白名单中'}` });
    } else {
      return sendMessage({ chat_id: ADMIN_UID, text: '⚠️ 格式错误。\n请回复用户消息发送 /checkwhite\n或发送 /checkwhite 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/listwhite - 列出所有白名单用户
  if (text === '/listwhite') {
    const whitelist = await getWhitelist();
    if (whitelist.length === 0) {
      return sendMessage({ chat_id: ADMIN_UID, text: '📋 白名单为空' });
    }
    return sendMessage({ chat_id: ADMIN_UID, text: `📋 白名单用户列表 (共 ${whitelist.length} 个):\n${whitelist.join('\n')}` });
  }

  // 指令：/bcancel - 取消广播（保留命令方式作为备选）
  if (text === '/bcancel') {
    await KV.delete(`broadcast_msg:${ADMIN_UID}`);
    return sendMessage({
      chat_id: ADMIN_UID,
      text: '✅ 已取消广播'
    });
  }

  // --- 普通回复逻辑 ---

  // 检查是否在回复转发消息或编辑提示消息
  if (reply) {
    let guestChatId = null;
    
    // 情况1：回复转发消息
    if (reply.forward_from || reply.forward_sender_name) {
      guestChatId = await KV.get('msg-map-' + reply.message_id);
    }
    // 情况2：回复编辑提示消息（以 ✏️ 开头）
    else if (reply.text && reply.text.startsWith('✏️')) {
      guestChatId = await KV.get('msg-map-' + reply.message_id);
    }
    
    if (guestChatId) {
      const copyReq = await copyMessage({
        chat_id: guestChatId,
        from_chat_id: message.chat.id,
        message_id: message.message_id,
      });
      
      // 存储管理员回复消息与访客收到消息的映射关系
      if (copyReq.ok && copyReq.result && copyReq.result.message_id) {
        await KV.put('admin-reply-map-' + message.message_id, JSON.stringify({
          guestChatId: guestChatId,
          guestMessageId: copyReq.result.message_id
        }), { expirationTtl: 172800 });
      }
      
      return copyReq;
    } else {
      return sendMessage({
        chat_id: ADMIN_UID,
        text: '⚠️ 未找到原用户映射，可能消息太旧或被清理了缓存。'
      });
    }
  } else {
    // 既不是指令也不是回复，提示使用 /help
    return sendMessage({
      chat_id: ADMIN_UID,
      text: '🤖 请发送 /help 查看所有可用指令，或直接回复用户消息进行转发。',
      parse_mode: 'HTML'
    });
  }
}

// 处理验证流程
async function handleVerification(message, chatId, origin) {
  // 生成验证链接
  const verifyUrl = `${origin}/verify?uid=${chatId}`;

  // 获取自定义欢迎消息，如果没有则使用默认
  const welcomeMsg = await getConfig(CONFIG_KEYS.WELCOME_MSG);
  const verificationText = welcomeMsg 
    ? welcomeMsg + '\n\n🛡 请完成下方验证以继续对话：'
    : '🛡 为了防止垃圾消息，请点击下方按钮完成人机验证：';

  return sendMessage({
    chat_id: chatId,
    text: verificationText,
    reply_markup: {
      inline_keyboard: [[
        { text: '🤖 点击进行人机验证', web_app: { url: verifyUrl } }
      ]]
    }
  });
}

// 渲染验证页面
function handleVerifyPage(request) {
  // 中文语言配置
  const t = {
    title: '人机验证 - SafeRelay',
    heading: '安全验证',
    subtitle: '请完成下方验证以继续对话',
    success: '验证成功！',
    successDesc: '请返回 Telegram 继续聊天',
    error: '验证失败',
    errorDesc: '请重试或刷新页面',
    retry: '重新验证',
    footer: '该界面由 SafeRelay 提供',
    loading: '验证中...'
  };
  
  const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${t.title}</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        * {
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        /* 浅色模式 - Soft UI 风格 */
        .theme-light {
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        }
        
        .theme-light .card {
            background: white;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.05), 0 10px 10px -5px rgba(0, 0, 0, 0.02);
        }
        
        .theme-light .icon-bg {
            background: #eef2ff;
        }
        
        .theme-light .icon-color {
            color: #6366f1;
        }
        
        .theme-light .text-primary {
            color: #1e293b;
        }
        
        .theme-light .text-secondary {
            color: #64748b;
        }
        
        .theme-light .error-bg {
            background: #fef2f2;
        }
        
        .theme-light .error-text {
            color: #dc2626;
        }
        
        .theme-light .success-bg {
            background: #f0fdf4;
        }
        
        .theme-light .success-icon {
            color: #16a34a;
        }
        
        /* 深色模式 - Soft UI 风格 */
        .theme-dark {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        }
        
        .theme-dark .card {
            background: #1e293b;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2);
        }
        
        .theme-dark .icon-bg {
            background: #312e81;
        }
        
        .theme-dark .icon-color {
            color: #818cf8;
        }
        
        .theme-dark .text-primary {
            color: #f1f5f9;
        }
        
        .theme-dark .text-secondary {
            color: #94a3b8;
        }
        
        .theme-dark .error-bg {
            background: rgba(220, 38, 38, 0.15);
        }
        
        .theme-dark .error-text {
            color: #f87171;
        }
        
        .theme-dark .success-bg {
            background: rgba(22, 163, 74, 0.15);
        }
        
        .theme-dark .success-icon {
            color: #4ade80;
        }
        
        /* 按钮样式 - Soft UI */
        .btn-primary {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 20px 25px -5px rgba(99, 102, 241, 0.4);
        }
        
        .btn-primary:active {
            transform: translateY(0);
        }
        
        .btn-secondary {
            background: #f1f5f9;
        }
        
        .theme-dark .btn-secondary {
            background: #334155;
        }
        
        .turnstile-container {
            min-height: 65px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .hidden {
            display: none !important;
        }
    </style>
</head>
<body class="theme-light min-h-screen flex items-center justify-center p-4 md:p-6">
    <div class="w-full max-w-md">
        <!-- 主卡片 - Soft UI 风格 -->
        <div class="card rounded-3xl p-6 md:p-8 text-center transition-all duration-300">
            <!-- 图标 -->
            <div class="icon-bg w-16 h-16 md:w-20 md:h-20 mx-auto mb-6 rounded-2xl flex items-center justify-center transition-all duration-300">
                <svg class="icon-color w-8 h-8 md:w-10 md:h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
            </div>
            
            <!-- 标题 -->
            <h1 class="text-primary text-xl md:text-2xl font-semibold mb-2 transition-colors duration-300">${t.heading}</h1>
            <p class="text-secondary text-sm md:text-base mb-8 transition-colors duration-300">${t.subtitle}</p>
            
            <!-- Turnstile 验证区域 -->
            <div id="verify-section" class="turnstile-container mb-6">
                <div id="turnstile-widget" class="cf-turnstile" data-sitekey="${CF_TURNSTILE_SITE_KEY}" data-callback="onVerify" data-theme="auto"></div>
            </div>
            
            <!-- 加载状态 -->
            <div id="loading-msg" class="hidden mb-6">
                <div class="inline-flex items-center gap-2 text-secondary">
                    <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span class="text-sm">${t.loading}</span>
                </div>
            </div>
            
            <!-- 成功消息 -->
            <div id="success-msg" class="hidden">
                <div class="success-bg w-14 h-14 md:w-16 md:h-16 mx-auto mb-4 rounded-2xl flex items-center justify-center transition-all duration-300">
                    <svg class="success-icon w-7 h-7 md:w-8 md:h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                </div>
                <h2 class="text-primary text-lg md:text-xl font-semibold mb-2 transition-colors duration-300">${t.success}</h2>
                <p class="text-secondary text-sm md:text-base transition-colors duration-300">${t.successDesc}</p>
            </div>
            
            <!-- 错误消息 -->
            <div id="error-msg" class="hidden mt-4">
                <div class="error-bg rounded-2xl p-4 mb-4 transition-all duration-300">
                    <p class="error-text text-sm font-medium">${t.error}</p>
                    <p class="text-secondary text-xs mt-1">${t.errorDesc}</p>
                </div>
                <!-- 重试按钮 -->
                <button onclick="resetVerification()" class="btn-primary text-white font-medium px-6 py-3 rounded-2xl transition-all duration-200">
                    ${t.retry}
                </button>
            </div>
        </div>
        
        <!-- 底部信息 -->
        <div class="mt-6 text-center">
            <p class="text-secondary text-xs transition-colors duration-300">${t.footer}</p>
        </div>
    </div>

    <script>
        // 初始化 Telegram Web App
        let tg;
        let currentTheme = 'light';
        
        try {
            tg = window.Telegram.WebApp;
            if (tg) {
                tg.ready();
                tg.expand();
                
                // 获取 Telegram 主题
                const themeParams = tg.themeParams;
                currentTheme = tg.colorScheme || 'light';
                
                // 应用主题
                applyTheme(currentTheme);
                
                // 监听主题变化
                tg.onEvent('themeChanged', function() {
                    currentTheme = tg.colorScheme || 'light';
                    applyTheme(currentTheme);
                });
            }
        } catch (e) {
            console.log('Telegram Web App 初始化失败:', e);
            // 检测系统主题
            if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                applyTheme('dark');
            }
        }
        
        // 应用主题
        function applyTheme(theme) {
            document.body.classList.remove('theme-light', 'theme-dark');
            document.body.classList.add('theme-' + theme);
            
            // 更新 Turnstile 主题
            const turnstileWidget = document.getElementById('turnstile-widget');
            if (turnstileWidget) {
                turnstileWidget.setAttribute('data-theme', theme);
            }
            
            // 更新 Telegram Web App 主题色
            if (tg) {
                const bgColor = theme === 'dark' ? '#0f172a' : '#f8fafc';
                tg.setHeaderColor(bgColor);
                tg.setBackgroundColor(bgColor);
            }
        }
        
        // 重置验证
        function resetVerification() {
            // 隐藏错误消息
            document.getElementById('error-msg').classList.add('hidden');
            
            // 显示验证区域
            document.getElementById('verify-section').classList.remove('hidden');
            
            // 重置 Turnstile
            if (typeof turnstile !== 'undefined') {
                turnstile.reset();
            } else {
                // 如果 Turnstile API 不可用，刷新页面
                window.location.reload();
            }
        }

        function onVerify(token) {
            const urlParams = new URLSearchParams(window.location.search);
            const uid = urlParams.get('uid');
            
            if (!uid) {
                showError();
                return;
            }
            
            // 显示加载状态
            document.getElementById('verify-section').classList.add('hidden');
            document.getElementById('loading-msg').classList.remove('hidden');

            // 获取用户信息
            let userInfo = null;
            try {
                if (tg && tg.initDataUnsafe && tg.initDataUnsafe.user) {
                    const user = tg.initDataUnsafe.user;
                    userInfo = {
                        id: user.id,
                        first_name: user.first_name || '',
                        last_name: user.last_name || '',
                        username: user.username || ''
                    };
                }
            } catch (e) {
                console.log('获取用户信息失败:', e);
            }

            fetch('/verify-callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, uid, userInfo })
            })
            .then(response => {
                if (response.ok) {
                    // 隐藏加载状态，显示成功消息
                    document.getElementById('loading-msg').classList.add('hidden');
                    document.getElementById('success-msg').classList.remove('hidden');
                    
                    // 验证成功 1.5 秒后尝试关闭窗口
                    setTimeout(() => {
                        try {
                            if (tg) {
                                tg.close();
                            }
                        } catch (e) {
                            console.log('关闭窗口失败:', e);
                        }
                    }, 1500);
                } else {
                    throw new Error('Verification failed');
                }
            })
            .catch(err => {
                console.error('验证失败:', err);
                showError();
            });
        }
        
        function showError() {
            document.getElementById('loading-msg').classList.add('hidden');
            document.getElementById('verify-section').classList.add('hidden');
            document.getElementById('error-msg').classList.remove('hidden');
        }
    </script>
</body>
</html>
  `;
  return new Response(html, {
    headers: { 'content-type': 'text/html;charset=UTF-8' }
  });
}

// 处理验证回调
async function handleVerifyCallback(request) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  try {
    const { token, uid, userInfo } = await request.json();

    if (!token || !uid) {
      return new Response('Missing token or uid', { status: 400 });
    }

    // 向 Cloudflare 验证 Token
    const formData = new FormData();
    formData.append('secret', CF_TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    // formData.append('remoteip', request.headers.get('CF-Connecting-IP')); // 可选

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData
    }).then(r => r.json());

    if (result.success) {
      // 验证通过！写入 KV
      const verifiedKey = 'verified-' + String(uid);
      await KV.put(verifiedKey, 'true', { expirationTtl: VERIFICATION_TTL });
      memSet(verifiedKey, 'true', 5 * 60 * 1000); // 更新缓存

      // 构建用户显示名称
      let displayName = 'Unknown';
      if (userInfo) {
        if (userInfo.first_name || userInfo.last_name) {
          displayName = `${userInfo.first_name || ''} ${userInfo.last_name || ''}`.trim();
        } else if (userInfo.username) {
          displayName = `@${userInfo.username}`;
        }
      }

      // 添加到已验证用户列表（带昵称）
      await addVerifiedUser(uid, displayName);

      // 主动通知用户验证成功
      await sendMessage({
        chat_id: uid,
        text: '✅ 验证通过！\n\n请等待 3-5 秒后再发送消息，以确保验证状态同步。'
      });

      // 通知管理员有新用户验证
      await sendMessage({
        chat_id: ADMIN_UID,
        text: `✅ <b>新用户验证通过</b>

UID: <code>${uid}</code>
昵称: ${escapeHtml(displayName)}

用户现在可以发送消息了。`,
        parse_mode: 'HTML'
      });

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({ success: false, error: result['error-codes'] }), {
        status: 400,
        headers: { 'content-type': 'application/json' }
      });
    }
  } catch (e) {
    return new Response(e.message, { status: 500 });
  }
}

// 获取验证有效期配置
async function getVerificationTtl() {
  const ttl = await getConfig(CONFIG_KEYS.VERIFY_TTL, VERIFICATION_TTL);
  return parseInt(ttl) || VERIFICATION_TTL;
}

// 处理访客消息 (已验证)
async function handleGuestMessage(message) {
  // 记录统计信息
  await incrementMessageCount();
  await recordActiveUser(message.chat.id.toString());
  
  return handleMediaGroup(message, async (messages) => {
    if (messages.length === 1) {
      // 单条消息，使用原来的转发方式
      const msg = messages[0];
      const forwardReq = await forwardMessage({
        chat_id: ADMIN_UID,
        from_chat_id: msg.chat.id,
        message_id: msg.message_id
      });

      if (forwardReq.ok && forwardReq.result && forwardReq.result.message_id) {
        await KV.put('msg-map-' + forwardReq.result.message_id, msg.chat.id.toString(), { expirationTtl: 172800 });
        await KV.put('orig-map-' + msg.message_id, forwardReq.result.message_id.toString(), { expirationTtl: 172800 });
      } else {
        await sendMessage({
          chat_id: ADMIN_UID,
          text: `❌ 转发消息失败：${JSON.stringify(forwardReq)}`
        });
      }
    } else {
      // 媒体组，批量转发
      const firstMsg = messages[0];
      const messageIds = messages.map(m => m.message_id);

      const forwardReq = await requestTelegram('forwardMessages', {
        chat_id: ADMIN_UID,
        from_chat_id: firstMsg.chat.id,
        message_ids: messageIds
      });

      if (forwardReq.ok && forwardReq.result) {
        // 存储映射关系
        for (let i = 0; i < messages.length; i++) {
          const origMsg = messages[i];
          const forwardedMsg = forwardReq.result[i];
          if (forwardedMsg && forwardedMsg.message_id) {
            await KV.put('msg-map-' + forwardedMsg.message_id, origMsg.chat.id.toString(), { expirationTtl: 172800 });
            await KV.put('orig-map-' + origMsg.message_id, forwardedMsg.message_id.toString(), { expirationTtl: 172800 });
          }
        }
      } else {
        await sendMessage({
          chat_id: ADMIN_UID,
          text: `❌ 批量转发消息失败：${JSON.stringify(forwardReq)}`
        });
      }
    }
  });
}

// 处理访客编辑后的消息
async function handleGuestEditedMessage(message) {
  const origMessageId = message.message_id.toString();
  const chatId = message.chat.id.toString();

  // 查找原始消息转发后的 ID（用于回复引用）
  const forwardedMessageId = await KV.get('orig-map-' + origMessageId);

  // 查找是否已有编辑提示消息
  const editNoticeKey = `edit-notice:${chatId}:${origMessageId}`;
  const existingNoticeId = await KV.get(editNoticeKey);

  const editNotice = `✏️ ${escapeHtml(message.text || '(无文本内容)')}`;

  if (existingNoticeId) {
    // 已有编辑提示，尝试更新
    try {
      const editReq = await requestTelegram('editMessageText', {
        chat_id: ADMIN_UID,
        message_id: parseInt(existingNoticeId),
        text: editNotice,
        parse_mode: 'HTML'
      });

      if (editReq.ok) {
        // 更新成功
        return;
      }
      // 更新失败（可能消息被删除），继续发送新消息
    } catch (e) {
      console.error('更新编辑提示失败:', e);
      // 继续发送新消息
    }
  }

  // 发送新的编辑提示
  const result = await sendMessage({
    chat_id: ADMIN_UID,
    text: editNotice,
    parse_mode: 'HTML',
    reply_to_message_id: forwardedMessageId || undefined
  });

  // 存储映射关系
  if (result.ok && result.result && result.result.message_id) {
    await KV.put('msg-map-' + result.result.message_id, chatId, { expirationTtl: 172800 });
    // 存储编辑提示消息ID，用于后续更新
    await KV.put(editNoticeKey, result.result.message_id.toString(), { expirationTtl: 172800 });
  }
}

// 处理管理员编辑后的消息
async function handleAdminEditedMessage(message) {
  const adminMessageId = message.message_id.toString();
  
  // 查找管理员回复消息的映射关系
  const replyMapData = await KV.get('admin-reply-map-' + adminMessageId);
  
  if (replyMapData) {
    try {
      const { guestChatId, guestMessageId } = JSON.parse(replyMapData);
      
      // 尝试编辑发送给访客的消息
      const editReq = await requestTelegram('editMessageText', {
        chat_id: guestChatId,
        message_id: guestMessageId,
        text: message.text || ''
      });
      
      if (!editReq.ok) {
        // 编辑失败，只通知管理员
        const errorCode = editReq.error_code;
        
        // 消息已过期或被删除 (错误码 400)
        if (errorCode === 400) {
          await sendMessage({
            chat_id: ADMIN_UID,
            text: `⚠️ 无法编辑消息：消息已过期或被删除（超过48小时）。\n\n如需修改，请直接发送新消息。`
          });
        } else {
          // 其他错误，只通知管理员编辑失败
          await sendMessage({
            chat_id: ADMIN_UID,
            text: `⚠️ 编辑消息失败：${editReq.description || '未知错误'}\n\n如需修改，请直接发送新消息。`
          });
        }
      }
    } catch (e) {
      // 解析映射数据失败
      await sendMessage({
        chat_id: ADMIN_UID,
        text: `❌ 处理编辑消息失败：${e.message}`
      });
    }
  } else {
    // 未找到映射关系，可能是旧消息或映射已过期
    await sendMessage({
      chat_id: ADMIN_UID,
      text: `⚠️ 未找到消息映射关系，无法同步编辑到用户。\n\n可能原因：消息已过期（超过48小时）或机器人已重启。`
    });
  }
}

// =================================================================
//                      Webhook 设置工具
// =================================================================

async function registerWebhook(event, requestUrl, suffix, secret) {
  const webhookUrl = `${requestUrl.protocol}//${requestUrl.hostname}${suffix}`;
  const r = await (await fetch(apiUrl('setWebhook', { url: webhookUrl, secret_token: secret }))).json();

  // 注册 Webhook 成功后设置命令列表
  if ('ok' in r && r.ok) {
    await setBotCommands();
  }

  return new Response('ok' in r && r.ok ? 'Ok' : JSON.stringify(r, null, 2));
}

async function unRegisterWebhook(event) {
  const r = await (await fetch(apiUrl('setWebhook', { url: '' }))).json();
  return new Response('ok' in r && r.ok ? 'Ok' : JSON.stringify(r, null, 2));
}
