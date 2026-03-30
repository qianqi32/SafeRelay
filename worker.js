/**
 * SafeRelay - Telegram 私聊机器人
 * 项目地址: https://github.com/qianqi32/SafeRelay
 * 版本: 1.0.6
 * 当前版本可能仍不稳定，如遇到 BUG 请提交至 issues
*/

// 基础配置
const getEnv = (key) => {
  if (typeof globalThis[key] !== 'undefined') return globalThis[key];
  if (typeof env !== 'undefined' && env[key]) return env[key];
  return undefined;
};

const TOKEN = getEnv('ENV_BOT_TOKEN');
const WEBHOOK = '/endpoint';
const SECRET = getEnv('ENV_BOT_SECRET');
const RAW_ADMIN_UID = getEnv('ENV_ADMIN_UID');
const ADMIN_IDS_ENV = getEnv('ADMIN_IDS');
const ADMIN_ID_LIST = parseAdminIdList(RAW_ADMIN_UID, ADMIN_IDS_ENV);
const ADMIN_ALLOWLIST = new Set(ADMIN_ID_LIST);
const ADMIN_UID = ADMIN_ID_LIST[0] || null;
const GROUP_ID = (() => {
  const value = getEnv('GROUP_ID');
  if (typeof value === 'undefined' || value === null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
})();

// 验证通过后的有效期 (秒)，默认 7 天
const VERIFICATION_TTL = 60 * 60 * 24 * 7;

// ========== 高级功能配置 ==========
const CONFIG = {
  // 消息暂存队列
  PENDING_MAX_MESSAGES: 10,           // 验证期间最多暂存消息数量
  PENDING_QUEUE_TTL_SECONDS: 86400,   // 暂存消息队列 TTL（秒）

  // KV 配额熔断保护
  KV_QUOTA_BREAKER_KEY: '__kv_quota_exceeded__',
  KV_QUOTA_NOTICE_COOLDOWN: 300,      // 5 分钟内只通知一次
  KV_QUOTA_BREAKER_TTL: 60,           // 熔断器持续时间（秒）

  // 用户资料缓存
  USER_PROFILE_CACHE_TTL: 86400,      // 用户资料缓存时间（秒）
  USER_PROFILE_COOLDOWN: 3600,        // 同一用户资料更新冷却（秒）

  // API 超时配置
  API_TIMEOUT_MS: 10000,              // Telegram API 调用超时（毫秒）

  // 验证并发保护
  VERIFY_LOCK_TTL_SECONDS: 60,        // 验证锁过期时间

  // 话题健康检查配置
  THREAD_HEALTH_TTL_MS: 30 * 60 * 1000,  // 话题健康状态缓存 TTL（30 分钟）
  THREAD_HEALTH_CHECK_TIMEOUT_MS: 5000,  // 话题探测超时（5 秒）

  // Workers AI 配置
  AI_SPAM_DETECTION_ENABLED: false,   // AI 垃圾检测开关（默认关闭）
  AI_MODEL_ID: '@cf/meta/llama-2-7b-chat-int8',  // AI 模型
  AI_CONFIDENCE_THRESHOLD: 0.7,       // AI 置信度阈值
  AI_RATE_LIMIT_PER_HOUR: 100,        // AI 每小时调用次数限制

  // 垃圾话题管理配置
  SPAM_TOPIC_ENABLED: false,          // 垃圾话题功能开关
  SPAM_TOPIC_ID: null,                // 垃圾话题 ID（可选，用于静默转发）

  // 数据安全性配置
  TURNSTILE_SESSION_TTL_MS: 10 * 60 * 1000, // Turnstile 会话有效期
};
const textEncoder = new TextEncoder();
let verificationSignKeyPromise = null;

function parseAdminIdList(primaryId, allowlistEnv) {
  const ids = [];
  const pushId = (value) => {
    if (!value && value !== 0) return;
    const normalized = String(value).trim();
    if (!normalized) return;
    if (!/^-?\d+$/.test(normalized)) return;
    if (!ids.includes(normalized)) {
      ids.push(normalized);
    }
  };

  if (allowlistEnv) {
    allowlistEnv.split(/[,;\s]+/).forEach(pushId);
  }
  pushId(primaryId);
  return ids;
}

function getTurnstileSiteKey() {
  return (getEnv('CF_TURNSTILE_SITE_KEY') || '').trim();
}

function getTurnstileSecretKey() {
  return (getEnv('CF_TURNSTILE_SECRET_KEY') || '').trim();
}

function getTurnstileAllowedHostnames() {
  const raw = (getEnv('TURNSTILE_ALLOWED_HOSTNAMES') || '').trim();
  if (!raw) return [];
  return raw.split(/[,;\s]+/).map(h => h.trim()).filter(Boolean);
}

function getTurnstileExpectedAction() {
  return (getEnv('TURNSTILE_ACTION') || '').trim();
}

function getVerificationSigningSecret() {
  return (getEnv('VERIFY_SIGNING_SECRET') || SECRET || TOKEN || '').toString();
}

async function getVerificationSignKey() {
  if (!verificationSignKeyPromise) {
    verificationSignKeyPromise = crypto.subtle.importKey(
      'raw',
      textEncoder.encode(getVerificationSigningSecret() || 'saferelay-signing-secret'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }
  return verificationSignKeyPromise;
}

async function signVerificationPayload(payload) {
  const key = await getVerificationSignKey();
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(payload));
  return bufferToBase64Url(signature);
}

function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}


// ========== 安全工具函数 ==========

/**
 * 加密安全的随机整数生成
 * @param {number} min - 最小值（包含）
 * @param {number} max - 最大值（不包含）
 * @returns {number} 随机整数
 */
function secureRandomInt(min, max) {
  const range = max - min;
  const bytes = new Uint32Array(1);
  crypto.getRandomValues(bytes);
  return min + (bytes[0] % range);
}

/**
 * 加密安全的随机 ID 生成
 * @param {number} length - ID 长度
 * @returns {string} 随机字符串
 */
function secureRandomId(length = 12) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

/**
 * 安全的 JSON 读取函数
 * 防止 KV 数据损坏或类型错误导致崩溃
 * @param {string} key - KV 键名
 * @param {any} defaultValue - 默认值
 * @returns {Promise<any>} 解析后的数据或默认值
 */
async function safeGetJSON(key, defaultValue = null) {
  try {
    const data = await KV.get(key);
    if (data === null || data === undefined) {
      return defaultValue;
    }
    const parsed = JSON.parse(data);
    // 确保返回的是对象类型（用于对象默认值）
    if (defaultValue !== null && typeof defaultValue === 'object' && typeof parsed !== 'object') {
      Logger.warn('kv_invalid_type', { key, expected: 'object', actual: typeof parsed });
      return defaultValue;
    }
    return parsed;
  } catch (e) {
    Logger.error('kv_parse_failed', e, { key });
    return defaultValue;
  }
}

/**
 * 恒定时间字符串比较（防止时序攻击）
 * @param {string} a - 字符串 a
 * @param {string} b - 字符串 b
 * @returns {boolean} 是否相等
 */
function constantTimeCompare(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

const TURNSTILE_SESSION_PREFIX = 'turnstile_session:';

async function createTurnstileSession(userId) {
  const sessionId = secureRandomId(32);
  const expiresAt = Date.now() + CONFIG.TURNSTILE_SESSION_TTL_MS;
  const payload = `${sessionId}.${userId}.${expiresAt}`;
  const signature = await signVerificationPayload(payload);
  await KV.put(
    `${TURNSTILE_SESSION_PREFIX}${sessionId}`,
    JSON.stringify({ userId, expiresAt }),
    { expirationTtl: Math.ceil(CONFIG.TURNSTILE_SESSION_TTL_MS / 1000) }
  );
  return { sessionId, signature, expiresAt };
}

async function validateTurnstileSession(sessionId, signature) {
  if (!sessionId || !signature) {
    return { valid: false };
  }

  const stored = await KV.get(`${TURNSTILE_SESSION_PREFIX}${sessionId}`);
  if (!stored) {
    return { valid: false };
  }

  let data;
  try {
    data = JSON.parse(stored);
  } catch (e) {
    Logger.error('turnstile_session_parse_failed', e);
    await KV.delete(`${TURNSTILE_SESSION_PREFIX}${sessionId}`);
    return { valid: false };
  }

  if (!data || !data.userId || !data.expiresAt) {
    await KV.delete(`${TURNSTILE_SESSION_PREFIX}${sessionId}`);
    return { valid: false };
  }

  if (Date.now() > data.expiresAt) {
    await KV.delete(`${TURNSTILE_SESSION_PREFIX}${sessionId}`);
    return { valid: false };
  }

  const expectedPayload = `${sessionId}.${data.userId}.${data.expiresAt}`;
  const expectedSig = await signVerificationPayload(expectedPayload);
  if (!constantTimeCompare(expectedSig, signature)) {
    return { valid: false };
  }

  return { valid: true, userId: data.userId };
}

async function consumeTurnstileSession(sessionId) {
  if (!sessionId) return;
  try {
    await KV.delete(`${TURNSTILE_SESSION_PREFIX}${sessionId}`);
  } catch (e) {
    Logger.warn('turnstile_session_delete_failed', { sessionId, error: e.message });
  }
}

// ========== 本地题库验证配置 ==========
// 验证模式: 'local_quiz'(默认本地题库) / 'turnstile'(Turnstile网页验证) / 'both'(两者都需要)
const VERIFY_MODE_DEFAULT = 'local_quiz';

// 本地题库题目
const LOCAL_QUIZ_QUESTIONS = [
  { q: "冰融化后会变成什么？", opts: ["水", "石头", "木头", "火"], a: 0 },
  { q: "正常人有几只眼睛？", opts: ["1", "2", "3", "4"], a: 1 },
  { q: "以下哪个属于水果？", opts: ["白菜", "香蕉", "猪肉", "大米"], a: 1 },
  { q: "1 加 2 等于几？", opts: ["2", "3", "4", "5"], a: 1 },
  { q: "5 减 2 等于几？", opts: ["1", "2", "3", "4"], a: 2 },
  { q: "2 乘以 3 等于几？", opts: ["4", "5", "6", "7"], a: 2 },
  { q: "10 加 5 等于几？", opts: ["10", "12", "15", "20"], a: 2 },
  { q: "8 减 4 等于几？", opts: ["2", "3", "4", "5"], a: 2 },
  { q: "在天上飞的交通工具是什么？", opts: ["汽车", "轮船", "飞机", "自行车"], a: 2 },
  { q: "星期一的后面是星期几？", opts: ["星期日", "星期五", "星期二", "星期三"], a: 2 },
  { q: "鱼通常生活在哪里？", opts: ["树上", "土里", "水里", "火里"], a: 2 },
  { q: "我们用什么器官来听声音？", opts: ["眼睛", "鼻子", "耳朵", "嘴巴"], a: 2 },
  { q: "晴朗的天空通常是什么颜色的？", opts: ["绿色", "红色", "蓝色", "紫色"], a: 2 },
  { q: "太阳从哪个方向升起？", opts: ["西方", "南方", "东方", "北方"], a: 2 },
  { q: "小狗发出的叫声通常是？", opts: ["喵喵", "咩咩", "汪汪", "呱呱"], a: 2 },
];

// 本地题库验证配置
const LOCAL_QUIZ_CONFIG = {
  CHALLENGE_TTL_SECONDS: 60,          // 单题有效期60秒
  TRIGGER_WINDOW_SECONDS: 300,        // 5分钟窗口
  TRIGGER_LIMIT: 3,                   // 5分钟最多触发3次
  MAX_ATTEMPTS: 3,                    // 每题最多尝试次数
};

// KV Key 常量
const KV_KEYS = {
  VERIFY_MODE: 'config:verify_mode',  // 验证模式配置
  SPAM_FILTER_ENABLED: 'config:spam_filter_enabled',  // 垃圾过滤开关
  SPAM_FILTER_RULES: 'config:spam_filter_rules',      // 垃圾过滤规则
  AI_SPAM_DETECTION: 'config:ai_spam_detection',      // AI 垃圾检测配置
  AI_USAGE_COUNT: 'stats:ai_usage:',                  // AI 使用统计（按小时）
  SPAM_TOPIC_CONFIG: 'config:spam_topic',              // 垃圾话题配置
};

// ========== 垃圾消息过滤配置 ==========
// 默认垃圾过滤规则
const DEFAULT_SPAM_RULES = {
  maxLinks: 3,                 // 最多允许3个链接
  keywords: [                  // 关键词列表
    "加群", "进群", "推广", "广告", "返利", "博彩", "代投", "套利",
    "USDT", "BTC", "ETH", "币圈", "空投", "交易所", "稳赚", "客服", "开户链接",
    "刷单", "兼职", "日赚", "高回报", "零风险", "投资", "理财", "赚钱"
  ],
  regexes: [                   // 正则表达式列表
    "\\b(?:usdt|btc|eth|trx|bnb)\\b",
    "(?:t\\.me/\\w+|telegram\\.me/\\w+)",
    "(?:免费|稳赚|日赚|高回报|带单|私聊我|加我)"
  ],
  allowKeywords: [],           // 放行关键词（白名单）
  allowRegexes: []             // 放行正则
};

// 结构化日志系统
const Logger = {
  info(action, data = {}) {
    const log = {
      timestamp: new Date().toISOString(),
      level: 'INFO',
      action,
      ...data
    };
    console.log(JSON.stringify(log));
  },

  warn(action, errorOrData = {}, data = {}) {
    let payload = {};
    if (errorOrData instanceof Error) {
      payload = { error: errorOrData.message, stack: errorOrData.stack, ...data };
    } else {
      payload = { ...errorOrData, ...data };
    }
    const log = {
      timestamp: new Date().toISOString(),
      level: 'WARN',
      action,
      ...payload
    };
    console.warn(JSON.stringify(log));
  },

  error(action, error, data = {}) {
    const log = {
      timestamp: new Date().toISOString(),
      level: 'ERROR',
      action,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      ...data
    };
    console.error(JSON.stringify(log));
  },

  debug(action, data = {}) {
    const log = {
      timestamp: new Date().toISOString(),
      level: 'DEBUG',
      action,
      ...data
    };
    console.log(JSON.stringify(log));
  },

  /**
   * 创建带上下文的日志记录器
   * @param {object} context - 上下文数据（如 userId, chatId 等）
   * @returns {object} 带上下文的日志方法
   */
  withContext(context) {
    return {
      info: (action, data = {}) => Logger.info(action, { ...context, ...data }),
      warn: (action, errorOrData = {}, data = {}) => Logger.warn(action, errorOrData, { ...context, ...data }),
      error: (action, error, data = {}) => Logger.error(action, error, { ...context, ...data }),
      debug: (action, data = {}) => Logger.debug(action, { ...context, ...data })
    };
  }
};

// 防刷屏配置（精细化速率限制）
const RATE_LIMIT_CONFIG = {
  // 普通消息频率限制
  message: {
    windowMs: 5000,      // 5 秒窗口
    maxRequests: 5,      // 最多 5 条消息
    keyPrefix: 'ratelimit:msg'
  },
  // 验证请求频率限制
  verify: {
    windowMs: 300000,    // 5 分钟窗口
    maxRequests: 3,      // 最多 3 次验证请求
    keyPrefix: 'ratelimit:verify'
  },
  // 验证答案尝试限制
  verifyAttempt: {
    windowMs: 60000,     // 1 分钟窗口
    maxRequests: 5,      // 最多 5 次尝试
    keyPrefix: 'ratelimit:attempt'
  },
  // 广播消息频率限制
  broadcast: {
    windowMs: 86400000,  // 24 小时窗口
    maxRequests: 1,      // 每天 1 次广播
    keyPrefix: 'ratelimit:broadcast'
  },
  // AI 检测频率限制
  aiDetect: {
    windowMs: 3600000,   // 1 小时窗口
    maxRequests: 100,    // 每小时 100 次 AI 检测
    keyPrefix: 'ratelimit:ai'
  },
  // 管理命令频率限制
  adminCommand: {
    windowMs: 60000,     // 1 分钟窗口
    maxRequests: 30,     // 每分钟 30 次命令
    keyPrefix: 'ratelimit:admin'
  }
};

// 限流增强配置
const RATE_LIMIT_ENHANCED = {
  // 是否启用分级限流（根据用户行为动态调整）
  enabledDynamicLimit: true,
  // 可信用户倍率（信任用户更宽松）
  trustedUserMultiplier: 2,
  // 新用户倍率（新用户更严格）
  newUserMultiplier: 0.5,
  // 最大累积惩罚次数
  maxPenaltyCount: 10,
  // 惩罚冷却时间（毫秒）
  penaltyCooldownMs: 300000  // 5 分钟
};

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
      Logger.error('union_ban_api_error', new Error(`HTTP ${resp.status}`), { endpoint });
      return null;
    }
    return await resp.json();
  } catch (e) {
    Logger.error('union_ban_api_network_error', e, { endpoint });
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
    Logger.error('fraud_db_check_failed', err);
    return false;
  }
}

// ========== 话题健康检查机制 ==========

// 话题健康状态缓存（内存缓存）
const threadHealthCache = new Map();

/**
 * 验证话题是否有效（带缓存）
 * @param {number} groupId - 群组 ID
 * @param {number} threadId - 话题 ID
 * @returns {Promise<boolean>} 话题是否有效
 */
async function validateForumThread(groupId, threadId) {
  if (!groupId || !threadId) return false;

  const cacheKey = `thread:${threadId}`;
  const now = Date.now();
  const cached = threadHealthCache.get(cacheKey);

  // 检查缓存
  if (cached && (now - cached.ts < CONFIG.THREAD_HEALTH_TTL_MS)) {
    return cached.ok;
  }

  // 缓存过期或不存在，进行健康探测
  const probeResult = await probeForumThread(groupId, threadId);

  // 更新缓存
  threadHealthCache.set(cacheKey, {
    ok: probeResult,
    ts: now
  });

  // 清理过期的缓存条目
  if (threadHealthCache.size > 1000) {
    for (const [key, value] of threadHealthCache.entries()) {
      if (now - value.ts > CONFIG.THREAD_HEALTH_TTL_MS) {
        threadHealthCache.delete(key);
      }
    }
  }

  return probeResult;
}

/**
 * 探测话题是否存在且可用
 * @param {number} groupId - 群组 ID
 * @param {number} threadId - 话题 ID
 * @returns {Promise<boolean>} 话题是否可用
 */
async function probeForumThread(groupId, threadId) {
  if (!groupId || !threadId) return false;
  try {
    const result = await requestTelegram('getForumTopic', {
      chat_id: groupId,
      message_thread_id: threadId
    });

    if (result.ok) {
      const topicInfo = result.result || {};
      if (topicInfo.closed || topicInfo.is_closed) {
        Logger.warn('thread_is_closed', { threadId, groupId });
        return false;
      }
      return true;
    }

    const desc = (result.description || '').toLowerCase();
    if (desc.includes('message thread not found') || desc.includes('topic not found')) {
      Logger.warn('thread_probe_missing', { threadId, groupId, error: result.description });
      return false;
    }
    if (desc.includes('not enough rights')) {
      Logger.warn('thread_probe_permission_denied', { threadId, groupId, error: result.description });
      await verifyTopicEnvironment({ force: true });
      return false;
    }
    if (desc.includes('method not found')) {
      return pingForumThread(groupId, threadId);
    }

    Logger.warn('thread_probe_unknown_error', { threadId, groupId, error: result.description });
    return true;
  } catch (e) {
    Logger.error('thread_probe_error', e, { threadId, groupId });
    return true;
  }
}

async function pingForumThread(groupId, threadId) {
  try {
    const probe = await requestTelegram('sendMessage', {
      chat_id: groupId,
      message_thread_id: threadId,
      text: '.',
      disable_notification: true
    });

    if (probe.ok && probe.result?.message_id) {
      await requestTelegram('deleteMessage', {
        chat_id: groupId,
        message_id: probe.result.message_id
      }).catch(err => Logger.warn('thread_probe_cleanup_failed', err, { groupId, threadId }));
      return true;
    }

    const desc = (probe.description || '').toLowerCase();
    if (desc.includes('message thread not found') || desc.includes('topic not found')) {
      Logger.warn('thread_probe_ping_missing', { threadId, groupId, error: probe.description });
      return false;
    }
    return true;
  } catch (e) {
    Logger.error('thread_probe_ping_error', e, { threadId, groupId });
    return true;
  }
}

/**
 * 重置用户验证状态并触发重新验证
 * @param {object} options - 选项
 * @param {string} options.userId - 用户 ID
 * @param {string} options.oldThreadId - 旧话题 ID
 * @param {number} options.pendingMsgId - 待处理消息 ID
 * @param {string} options.reason - 原因
 */
async function resetUserVerificationAndRequireReverify({
  userId,
  oldThreadId,
  pendingMsgId,
  reason = 'topic_invalid'
}) {
  try {
    Logger.info('resetting_user_verification', {
      userId,
      oldThreadId,
      reason
    });

    // 删除旧的 thread 映射
    if (oldThreadId) {
      await safeKvDelete(`thread:${oldThreadId}`);
    }

    // 删除用户验证状态
    await safeKvDelete(`verified-${userId}`);
    await safeKvDelete(`user:${userId}`);

    // 清理内存缓存
    memDelete(`verified-${userId}`);
    memDelete(`user:${userId}`);
    if (oldThreadId) {
      threadHealthCache.delete(`thread:${oldThreadId}`);
    }

    // 通知用户需要重新验证
    await sendMessage({
      chat_id: userId,
      text: '⚠️ <b>验证失效通知</b>\n\n您的话题可能已被删除或失效，需要重新验证。\n\n请点击 /start 重新开始验证流程。',
      parse_mode: 'HTML'
    });

    Logger.info('user_verification_reset_complete', { userId, reason });

  } catch (e) {
    Logger.error('reset_verification_failed', e, { userId, reason });
  }
}

// ========== 本地题库验证函数 ==========

// 检查 Turnstile 是否已配置
function hasTurnstileConfigured() {
  const site = getTurnstileSiteKey();
  const secret = getTurnstileSecretKey();
  return !!(site && secret);
}

// 获取当前验证模式
async function getVerifyMode() {
  const mode = await KV.get(KV_KEYS.VERIFY_MODE);
  if (mode === 'turnstile') return hasTurnstileConfigured() ? 'turnstile' : 'local_quiz';
  if (mode === 'both') return hasTurnstileConfigured() ? 'both' : 'local_quiz';
  return 'local_quiz'; // 默认本地题库
}

// 设置验证模式
async function setVerifyMode(mode) {
  if (mode === 'turnstile' && !hasTurnstileConfigured()) return false;
  if (mode === 'both' && !hasTurnstileConfigured()) return false;
  if (!['local_quiz', 'turnstile', 'both'].includes(mode)) return false;
  await KV.put(KV_KEYS.VERIFY_MODE, mode);
  return true;
}

// 获取验证模式显示名称
function getVerifyModeName(mode) {
  const names = {
    'local_quiz': '📝 本地题库',
    'turnstile': '☁️ Turnstile',
    'both': '🔒 双重验证'
  };
  return names[mode] || mode;
}

// 检查本地题库触发频率限制
async function checkLocalQuizTriggerLimit(userId) {
  const key = `quiz_trigger:${userId}`;
  const now = Date.now();
  const windowMs = LOCAL_QUIZ_CONFIG.TRIGGER_WINDOW_SECONDS * 1000;

  let timestamps = [];
  try {
    const data = await KV.get(key);
    if (data) timestamps = JSON.parse(data);
  } catch (e) { /* ignore */ }

  if (!Array.isArray(timestamps)) timestamps = [];

  // 过滤掉过期的记录
  timestamps = timestamps.filter(ts => (now - ts) < windowMs);

  if (timestamps.length >= LOCAL_QUIZ_CONFIG.TRIGGER_LIMIT) {
    return { allowed: false, count: timestamps.length };
  }

  // 添加新记录
  timestamps.push(now);
  await KV.put(key, JSON.stringify(timestamps), {
    expirationTtl: Math.max(LOCAL_QUIZ_CONFIG.TRIGGER_WINDOW_SECONDS * 2, 60)
  });

  return { allowed: true, count: timestamps.length };
}

// 创建新的验证题目
async function createQuizChallenge(userId) {
  // 【安全改进】使用加密安全的随机数
  const questionIndex = secureRandomInt(0, LOCAL_QUIZ_QUESTIONS.length);
  const question = LOCAL_QUIZ_QUESTIONS[questionIndex];

  // 【安全改进】使用加密安全的随机 ID
  const challengeId = `quiz_${Date.now()}_${secureRandomId(9)}`;

  // 存储题目信息到KV
  const challengeData = {
    questionIndex: questionIndex,
    correctAnswer: question.a,
    createdAt: Date.now(),
    attempts: 0
  };

  await KV.put(`quiz_challenge:${userId}`, JSON.stringify(challengeData), {
    expirationTtl: LOCAL_QUIZ_CONFIG.CHALLENGE_TTL_SECONDS
  });

  return { challengeId, question };
}

// 获取当前验证题目（带自愈机制）
async function getQuizChallenge(userId) {
  // 【安全改进】使用 safeGetJSON 防止数据损坏导致崩溃
  const challenge = await safeGetJSON(`quiz_challenge:${userId}`, null);

  // 【自愈机制】检查数据完整性
  if (challenge) {
    const isValid = (
      typeof challenge === 'object' &&
      typeof challenge.questionIndex === 'number' &&
      typeof challenge.correctAnswer === 'number' &&
      typeof challenge.attempts === 'number' &&
      challenge.questionIndex >= 0 &&
      challenge.questionIndex < LOCAL_QUIZ_QUESTIONS.length &&
      challenge.correctAnswer >= 0 &&
      challenge.correctAnswer <= 3
    );

    if (!isValid) {
      Logger.warn('invalid_challenge_data_detected', { userId, challenge });
      // 清理损坏的数据
      await deleteQuizChallenge(userId);
      return null;
    }
  }

  return challenge;
}

// 删除验证题目
async function deleteQuizChallenge(userId) {
  await KV.delete(`quiz_challenge:${userId}`);
}

// ========== 并发验证锁机制 ==========

/**
 * 尝试获取验证锁
 * @param {string} userId - 用户 ID
 * @returns {Promise<{acquired: boolean, lockInfo: object|null}>} 是否成功获取锁
 */
async function tryAcquireVerifyLock(userId) {
  const lockKey = `verify_lock:${userId}`;
  const now = Date.now();

  try {
    // 尝试获取锁
    const lockData = await KV.get(lockKey);

    if (!lockData) {
      // 锁不存在，可以获取
      const newLock = {
        acquiredAt: now,
        expiresAt: now + (CONFIG.VERIFY_LOCK_TTL_SECONDS * 1000)
      };

      await KV.put(lockKey, JSON.stringify(newLock), {
        expirationTtl: CONFIG.VERIFY_LOCK_TTL_SECONDS + 10 // 多给 10 秒缓冲
      });

      Logger.debug('verify_lock_acquired', { userId });
      return { acquired: true, lockInfo: newLock };
    }

    // 锁已存在，检查是否过期
    const lockInfo = JSON.parse(lockData);
    if (lockInfo.expiresAt < now) {
      // 锁已过期，可以重新获取
      const newLock = {
        acquiredAt: now,
        expiresAt: now + (CONFIG.VERIFY_LOCK_TTL_SECONDS * 1000)
      };

      await KV.put(lockKey, JSON.stringify(newLock), {
        expirationTtl: CONFIG.VERIFY_LOCK_TTL_SECONDS + 10
      });

      Logger.debug('verify_lock_reacquired', { userId, expiredAt: lockInfo.expiresAt });
      return { acquired: true, lockInfo: newLock };
    }

    // 锁未过期，拒绝获取
    const remainingMs = lockInfo.expiresAt - now;
    Logger.debug('verify_lock_busy', { userId, remainingMs });
    return { acquired: false, lockInfo: { ...lockInfo, remainingMs } };

  } catch (e) {
    Logger.error('verify_lock_error', e, { userId });
    // 出错时允许继续，避免锁死
    return { acquired: true, lockInfo: null };
  }
}

/**
 * 释放验证锁
 * @param {string} userId - 用户 ID
 */
async function releaseVerifyLock(userId) {
  const lockKey = `verify_lock:${userId}`;
  try {
    await KV.delete(lockKey);
    Logger.debug('verify_lock_released', { userId });
  } catch (e) {
    Logger.error('verify_lock_release_error', e, { userId });
  }
}

// 验证答案
async function verifyQuizAnswer(userId, answerIndex) {
  const challenge = await getQuizChallenge(userId);
  if (!challenge) {
    return { success: false, reason: 'expired', message: '验证已过期，请重新获取题目' };
  }

  // 检查尝试次数
  if (challenge.attempts >= LOCAL_QUIZ_CONFIG.MAX_ATTEMPTS) {
    await deleteQuizChallenge(userId);
    return { success: false, reason: 'max_attempts', message: '尝试次数过多，请重新获取题目' };
  }

  // 更新尝试次数
  challenge.attempts++;
  await KV.put(`quiz_challenge:${userId}`, JSON.stringify(challenge), {
    expirationTtl: LOCAL_QUIZ_CONFIG.CHALLENGE_TTL_SECONDS
  });

  // 验证答案
  if (answerIndex === challenge.correctAnswer) {
    await deleteQuizChallenge(userId);
    return { success: true };
  }

  const remaining = LOCAL_QUIZ_CONFIG.MAX_ATTEMPTS - challenge.attempts;
  return {
    success: false,
    reason: 'wrong_answer',
    message: `答案错误，还剩 ${remaining} 次机会`,
    remaining
  };
}

// 生成题目 Inline Keyboard
function generateQuizKeyboard(question) {
  const buttons = question.opts.map((opt, idx) => ({
    text: opt,
    callback_data: `quiz_answer:${idx}`
  }));
  // 每行2个按钮
  const keyboard = [];
  for (let i = 0; i < buttons.length; i += 2) {
    keyboard.push(buttons.slice(i, i + 2));
  }
  return { inline_keyboard: keyboard };
}

// ========== 垃圾消息过滤函数 ==========

// 获取垃圾过滤开关状态
async function getSpamFilterEnabled() {
  const enabled = await KV.get(KV_KEYS.SPAM_FILTER_ENABLED);
  // 默认开启
  return enabled !== '0' && enabled !== 'false';
}

// 设置垃圾过滤开关
async function setSpamFilterEnabled(enabled) {
  await KV.put(KV_KEYS.SPAM_FILTER_ENABLED, enabled ? '1' : '0');
}

// 获取垃圾过滤规则
async function getSpamFilterRules() {
  try {
    const rules = await KV.get(KV_KEYS.SPAM_FILTER_RULES);
    if (!rules) return DEFAULT_SPAM_RULES;
    return JSON.parse(rules);
  } catch (e) {
    return DEFAULT_SPAM_RULES;
  }
}

// 设置垃圾过滤规则
async function setSpamFilterRules(rules) {
  await KV.put(KV_KEYS.SPAM_FILTER_RULES, JSON.stringify(rules));
}

// 重置为默认规则
async function resetSpamFilterRules() {
  await KV.put(KV_KEYS.SPAM_FILTER_RULES, JSON.stringify(DEFAULT_SPAM_RULES));
  return DEFAULT_SPAM_RULES;
}

// 统计文本中的链接数量
function countLinks(text) {
  if (!text) return 0;
  // 匹配 http/https 链接和 t.me 链接
  const linkRegex = /(https?:\/\/[^\s]+|t\.me\/\w+|telegram\.me\/\w+)/gi;
  const matches = text.match(linkRegex);
  return matches ? matches.length : 0;
}

// 检查是否为垃圾消息
async function checkSpam(message, userId = null) {
  // 获取开关状态
  const enabled = await getSpamFilterEnabled();
  if (!enabled) return { isSpam: false, reason: null };

  // 获取规则
  const rules = await getSpamFilterRules();

  // 提取文本内容
  let text = '';
  if (message.text) text = message.text;
  else if (message.caption) text = message.caption;

  if (!text) return { isSpam: false, reason: null };

  const lowerText = text.toLowerCase();

  // 1. 检查放行关键词（白名单优先）
  for (const keyword of rules.allowKeywords || []) {
    if (lowerText.includes(keyword.toLowerCase())) {
      return { isSpam: false, reason: null };
    }
  }

  // 2. 检查放行正则
  for (const regexStr of rules.allowRegexes || []) {
    try {
      const regex = new RegExp(regexStr, 'i');
      if (regex.test(text)) {
        return { isSpam: false, reason: null };
      }
    } catch (e) { /* 忽略无效正则 */ }
  }

  // 3. 检查链接数量
  const linkCount = countLinks(text);
  if (rules.maxLinks > 0 && linkCount >= rules.maxLinks) {
    return { isSpam: true, reason: `链接过多 (${linkCount}/${rules.maxLinks})` };
  }

  // 4. 检查关键词
  for (const keyword of rules.keywords || []) {
    if (lowerText.includes(keyword.toLowerCase())) {
      return { isSpam: true, reason: `命中关键词: ${keyword}` };
    }
  }

  // 5. 检查正则
  for (const regexStr of rules.regexes || []) {
    try {
      const regex = new RegExp(regexStr, 'i');
      if (regex.test(text)) {
        return { isSpam: true, reason: '命中正则规则' };
      }
    } catch (e) { /* 忽略无效正则 */ }
  }

  // 6. AI 检测（可选，需要配置 Workers AI）
  const aiResult = await checkSpamWithAI(text, userId);
  if (aiResult.isSpam) {
    return aiResult;
  }

  return { isSpam: false, reason: null };
}

// ========== 垃圾话题管理 ==========

// 获取垃圾话题配置
async function getSpamTopicConfig() {
  return await safeGetJSON(KV_KEYS.SPAM_TOPIC_CONFIG, {
    enabled: CONFIG.SPAM_TOPIC_ENABLED,
    topicId: CONFIG.SPAM_TOPIC_ID,
    autoCreate: false,
    notifyAdmin: true
  });
}

// 设置垃圾话题配置
async function setSpamTopicConfig(config) {
  await KV.put(KV_KEYS.SPAM_TOPIC_CONFIG, JSON.stringify(config));
}

// 检查垃圾话题功能是否启用
async function isSpamTopicEnabled() {
  const config = await getSpamTopicConfig();
  return config.enabled === true;
}

// 创建垃圾话题
async function createSpamTopic(groupId) {
  try {
    // 先尝试获取已有的垃圾话题（通过列出所有话题）
    const listResponse = await requestTelegram('getForumTopicInfo', {
      chat_id: groupId,
      message_thread_id: 1 // 先尝试 General 话题
    });

    // 尝试创建一个新话题
    const response = await requestTelegram('createForumTopic', {
      chat_id: groupId,
      name: '🗑 垃圾消息回收站',
      icon_color: 0x8E8E8E  // 灰色图标
    });

    if (response && response.ok) {
      const topicId = response.result.message_thread_id;
      Logger.info('spam_topic_created', { groupId, topicId });
      return topicId;
    }

    // 如果创建失败，检查是否是因为话题已存在
    if (response && response.description && response.description.includes('TOPIC_TITLE_IS_EMPTY')) {
      Logger.warn('spam_topic_create_invalid', { groupId, description: response.description });
    }

    if (response && response.description && (response.description.includes('TOPIC_CLOSED') || response.description.includes('TOPIC_NOT_FOUND'))) {
      Logger.error('spam_topic_create_failed', { groupId, description: response.description });
    }

    return null;
  } catch (e) {
    Logger.error('create_spam_topic_failed', e, { groupId });
    return null;
  }
}

// 转发消息到垃圾话题
async function forwardToSpamTopic(message, groupId, topicId) {
  try {
    await forwardMessage({
      chat_id: groupId,
      message_thread_id: topicId,
      from_chat_id: message.chat.id,
      message_id: message.message_id
    });
    return true;
  } catch (e) {
    Logger.error('forward_to_spam_topic_failed', e, { topicId });
    return false;
  }
}

// 静默转发垃圾消息（用户无感知）
async function silentlyForwardSpamMessage(message, groupId, topicId) {
  try {
    // 转发到垃圾话题
    await forwardToSpamTopic(message, groupId, topicId);

    // 通知管理员
    await sendMessage({
      chat_id: ADMIN_UID,
      text: `🗑 <b>垃圾消息已静默处理</b>\n\nUID: <code>${message.from?.id}</code>\n话题 ID: <code>${topicId}</code>\n\n<i>消息已转发到垃圾话题，用户无感知</i>`,
      parse_mode: 'HTML'
    });

    return true;
  } catch (e) {
    Logger.error('silently_forward_spam_failed', e);
    return false;
  }
}

// 从垃圾话题恢复消息
async function restoreMessageFromSpamTopic(groupId, spamTopicId, targetTopicId, messageId) {
  try {
    // 转发回正常话题
    await forwardMessage({
      chat_id: groupId,
      message_thread_id: targetTopicId,
      from_chat_id: groupId,
      message_id: messageId
    });

    Logger.info('message_restored_from_spam', { groupId, spamTopicId, targetTopicId, messageId });
    return true;
  } catch (e) {
    Logger.error('restore_message_failed', e);
    return false;
  }
}

// ========== 用户话题管理 ==========
async function ensureUserTopic(userId, profile = null) {
  if (!GROUP_ID) {
    Logger.warn('ensure_user_topic_no_group_id', { userId });
    return null;
  }

  // 尝试验证环境，但即使验证失败也尝试继续
  const topicEnv = await verifyTopicEnvironment({ notifyOnFailure: false });
  Logger.info('ensure_user_topic_env_check', { userId, topicEnv });

  const userKey = `user:${userId}`;
  let userData = await safeGetJSON(userKey, null);

  if (userData && userData.thread_id) {
    const healthy = await validateForumThread(GROUP_ID, userData.thread_id);
    Logger.info('ensure_user_topic_thread_health', { userId, threadId: userData.thread_id, healthy });
    if (healthy) {
      return { threadId: userData.thread_id, userData, newlyCreated: false };
    }

    try {
      await safeKvDelete(`thread:${userData.thread_id}`);
    } catch (e) {
      Logger.warn('cleanup_stale_thread_failed', e, { threadId: userData.thread_id });
    }
  }

  const lockToken = await acquireTopicLock(userId);
  if (!lockToken) {
    Logger.warn('topic_lock_acquire_failed', { userId });
  }

  try {
    userData = await safeGetJSON(userKey, null);
    if (userData && userData.thread_id) {
      const healthy = await validateForumThread(GROUP_ID, userData.thread_id);
      if (healthy) {
        return { threadId: userData.thread_id, userData, newlyCreated: false };
      }
      try {
        await safeKvDelete(`thread:${userData.thread_id}`);
      } catch (e) {
        Logger.warn('cleanup_stale_thread_failed', e, { threadId: userData.thread_id });
      }
    }

    if (!profile) {
      profile = await getUserProfile(userId);
    }

    Logger.info('ensure_user_topic_creating_thread', { userId });
    const threadId = await createUserTopicThread(userId, profile);
    Logger.info('ensure_user_topic_thread_created', { userId, threadId });
    if (!threadId) {
      return null;
    }

    const record = {
      user_id: userId,
      thread_id: threadId,
      username: profile?.username || null,
      first_name: profile?.first_name || '',
      last_name: profile?.last_name || '',
      updated_at: Date.now()
    };

    await safeKvPut(userKey, JSON.stringify(record));
    await safeKvPut(`thread:${threadId}`, userId);
    threadHealthCache.set(`thread:${threadId}`, { ok: true, ts: Date.now() });

    return { threadId, userData: record, newlyCreated: true };
  } finally {
    await releaseTopicLock(userId, lockToken);
  }
}

async function invalidateUserTopicMapping(userId, threadId = null) {
  try {
    if (threadId) {
      await safeKvDelete(`thread:${threadId}`);
      threadHealthCache.delete(`thread:${threadId}`);
      try {
        await KV.delete(`thread_ok:${threadId}`);
      } catch (e) {
        Logger.warn('thread_ok_delete_failed', e, { threadId });
      }
    }
    await safeKvDelete(`user:${userId}`);
    memDelete(`user:${userId}`);
  } catch (e) {
    Logger.warn('invalidate_user_topic_failed', e, { userId, threadId });
  }

  if (ADMIN_UID) {
    const noticeKey = `topic_recover:${userId}`;
    const lastNotice = memGet(noticeKey);
    if (!lastNotice) {
      await sendMessage({
        chat_id: ADMIN_UID,
        text: `⚠️ 访客 ${userId} 的话题已失效，正在尝试重新创建。`
      }).catch(() => { });
      memSet(noticeKey, Date.now(), 5 * 60 * 1000);
    }
  }
}

async function createUserTopicThread(userId, profile = null) {
  if (!GROUP_ID) {
    Logger.error('create_user_topic_no_group_id', { userId });
    return null;
  }

  const groupIdStr = String(GROUP_ID);
  Logger.info('create_user_topic_group_id_check', { userId, GROUP_ID, startsWithMinus100: groupIdStr.startsWith('-100') });

  if (!groupIdStr.startsWith('-100')) {
    Logger.error('create_user_topic_invalid_group_id', {
      userId,
      GROUP_ID,
      hint: '群组ID必须以-100开头，请使用超级群组！'
    });
  }

  const topicTitle = buildUserTopicTitle(userId, profile);
  Logger.info('create_user_topic_starting', { userId, topicTitle });

  try {
    const response = await requestTelegram('createForumTopic', {
      chat_id: GROUP_ID,
      name: topicTitle
    });

    Logger.info('create_user_topic_response', { userId, ok: response?.ok, description: response?.description });

    if (!response || !response.ok) {
      Logger.error('create_user_topic_failed', {
        userId,
        description: response?.description
      });
      return null;
    }

    const threadId = response.result.message_thread_id;
    Logger.info('create_user_topic_got_thread_id', { userId, threadId });

    try {
      await sendTopicWelcomeMessage(threadId, userId, profile);
    } catch (welcomeErr) {
      Logger.warn('send_topic_welcome_failed', welcomeErr, { userId, threadId });
    }

    Logger.info('user_topic_created', { userId, threadId, topicTitle });
    return threadId;
  } catch (e) {
    Logger.error('create_user_topic_error', e, { userId });
    return null;
  }
}

async function acquireTopicLock(userId) {
  const lockKey = `topic_lock:${userId}`;
  const token = secureRandomId(16);
  for (let attempt = 0; attempt < 5; attempt++) {
    await KV.put(lockKey, token, { expirationTtl: 60 });
    const stored = await KV.get(lockKey);
    if (stored === token) {
      return token;
    }
    await new Promise(resolve => setTimeout(resolve, 50 * (attempt + 1)));
  }
  return null;
}

async function releaseTopicLock(userId, token) {
  if (!token) return;
  const lockKey = `topic_lock:${userId}`;
  try {
    const stored = await KV.get(lockKey);
    if (stored === token) {
      await KV.delete(lockKey);
    }
  } catch (e) {
    Logger.warn('release_topic_lock_failed', e, { userId });
  }
}

function buildUserTopicTitle(userId, profile = null) {
  const parts = [];
  if (profile) {
    if (profile.first_name || profile.last_name) {
      parts.push(`${profile.first_name || ''} ${profile.last_name || ''}`.trim());
    }
    if (profile.username) {
      parts.push(`@${profile.username}`);
    }
  }

  let base = parts.filter(Boolean).join(' ');
  if (!base) base = `访客 ${userId}`;

  let title = `#${userId} ${base}`.trim();
  if (title.length > 60) {
    title = title.slice(0, 60);
  }
  return title;
}

async function sendTopicWelcomeMessage(threadId, userId, profile = null) {
  if (!GROUP_ID) return;
  try {
    const lines = [
      '👤 <b>新访客对话</b>',
      `UID：<code>${userId}</code>`
    ];
    if (profile?.username) {
      lines.push(`用户名：@${escapeHtml(profile.username)}`);
    }
    if (profile?.first_name || profile?.last_name) {
      lines.push(`姓名：${escapeHtml(`${profile.first_name || ''} ${profile.last_name || ''}`.trim())}`);
    }
    lines.push('\n请在此话题内回复用户消息。');

    await sendMessage({
      chat_id: GROUP_ID,
      message_thread_id: threadId,
      text: lines.join('\n'),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true }
    });
  } catch (e) {
    Logger.warn('topic_welcome_message_failed', e, { userId, threadId });
  }
}

// ========== Workers AI 垃圾检测 ==========

// 检查 AI 检测是否启用
async function isAISpamDetectionEnabled() {
  const config = await safeGetJSON(KV_KEYS.AI_SPAM_DETECTION, {
    enabled: CONFIG.AI_SPAM_DETECTION_ENABLED,
    confidenceThreshold: CONFIG.AI_CONFIDENCE_THRESHOLD
  });
  return config.enabled === true;
}

// 设置 AI 检测配置
async function setAISpamDetectionConfig(config) {
  await KV.put(KV_KEYS.AI_SPAM_DETECTION, JSON.stringify(config));
}

// 获取 AI 检测配置
async function getAISpamDetectionConfig() {
  return await safeGetJSON(KV_KEYS.AI_SPAM_DETECTION, {
    enabled: CONFIG.AI_SPAM_DETECTION_ENABLED,
    confidenceThreshold: CONFIG.AI_CONFIDENCE_THRESHOLD
  });
}

// 检查 AI 使用速率限制
async function checkAIRateLimit() {
  const now = Date.now();
  const hourKey = `${KV_KEYS.AI_USAGE_COUNT}${Math.floor(now / 3600000)}`;

  const count = await KV.get(hourKey);
  const currentCount = count ? parseInt(count) : 0;

  if (currentCount >= CONFIG.AI_RATE_LIMIT_PER_HOUR) {
    return { allowed: false, remaining: 0, resetAfter: 3600 - Math.floor((now % 3600000) / 1000) };
  }

  return { allowed: true, remaining: CONFIG.AI_RATE_LIMIT_PER_HOUR - currentCount };
}

// 增加 AI 使用计数
async function incrementAIUsage() {
  const now = Date.now();
  const hourKey = `${KV_KEYS.AI_USAGE_COUNT}${Math.floor(now / 3600000)}`;
  const currentCount = await KV.get(hourKey);
  const newCount = (currentCount ? parseInt(currentCount) : 0) + 1;

  await KV.put(hourKey, String(newCount), { expirationTtl: 7200 });
}

// 使用 Workers AI 检测垃圾消息
async function checkSpamWithAI(text, userId = null) {
  // 检查 AI 是否启用
  const aiEnabled = await isAISpamDetectionEnabled();
  if (!aiEnabled) {
    return { isSpam: false, reason: null, aiSkipped: true };
  }

  // 检查速率限制
  const rateLimit = await checkAIRateLimit();
  if (!rateLimit.allowed) {
    Logger.warn('ai_rate_limit_exceeded', { userId, remainingReset: rateLimit.resetAfter });
    return { isSpam: false, reason: null, aiSkipped: true, rateLimited: true };
  }

  // 检查文本长度（太短不需要 AI 检测）
  if (text.length < 20) {
    return { isSpam: false, reason: null, aiSkipped: true, tooShort: true };
  }

  try {
    // 构建 AI 提示词
    const prompt = `请判断以下消息是否为垃圾广告消息。只回答"spam"或"not_spam"。
    
消息内容：
${text}

判断标准：
- 包含推广、营销、投资、理财、博彩等内容 → spam
- 包含多个链接或联系方式 → spam
- 正常交流、提问、聊天 → not_spam

你的回答（只回答 spam 或 not_spam）：`;

    // 调用 Workers AI
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${getEnv('CF_ACCOUNT_ID')}/ai/run/${CONFIG.AI_MODEL_ID}`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${getEnv('CF_AI_TOKEN')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messages: [
            { role: 'user', content: prompt }
          ],
          max_tokens: 10,
          temperature: 0.1
        })
      }
    );

    if (!response.ok) {
      Logger.error('ai_api_call_failed', { status: response.status });
      return { isSpam: false, reason: null, aiSkipped: true, apiError: true };
    }

    const result = await response.json();
    const aiResponse = result.result?.response?.trim().toLowerCase() || '';

    // 增加使用计数
    await incrementAIUsage();

    // 判断结果
    const isSpam = aiResponse.includes('spam') && !aiResponse.includes('not_spam');

    if (isSpam) {
      Logger.info('ai_detected_spam', { userId, text: text.substring(0, 50) });
      return {
        isSpam: true,
        reason: 'AI 识别为垃圾消息',
        aiConfidence: 0.8,
        aiResponse
      };
    }

    return { isSpam: false, reason: null, aiChecked: true };

  } catch (e) {
    Logger.error('ai_detection_failed', e, { userId });
    return { isSpam: false, reason: null, aiSkipped: true, error: true };
  }
}

// 格式化规则为可读文本
function formatSpamRules(rules) {
  const lines = [];
  lines.push(`<b>链接限制:</b> 最多 ${rules.maxLinks} 个`);

  if (rules.keywords && rules.keywords.length > 0) {
    lines.push(`\n<b>拦截关键词 (${rules.keywords.length}个):</b>`);
    lines.push(rules.keywords.slice(0, 10).join(', '));
    if (rules.keywords.length > 10) {
      lines.push(`... 等共 ${rules.keywords.length} 个`);
    }
  }

  if (rules.regexes && rules.regexes.length > 0) {
    lines.push(`\n<b>拦截正则 (${rules.regexes.length}个):</b>`);
    rules.regexes.slice(0, 3).forEach(r => lines.push(`• ${r}`));
    if (rules.regexes.length > 3) {
      lines.push(`... 等共 ${rules.regexes.length} 个`);
    }
  }

  if (rules.allowKeywords && rules.allowKeywords.length > 0) {
    lines.push(`\n<b>放行关键词:</b> ${rules.allowKeywords.join(', ')}`);
  }

  return lines.join('\n');
}

// 解析规则编辑文本
function parseSpamRulesEdit(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  const rules = {
    maxLinks: DEFAULT_SPAM_RULES.maxLinks,
    keywords: [...DEFAULT_SPAM_RULES.keywords],
    regexes: [...DEFAULT_SPAM_RULES.regexes],
    allowKeywords: [],
    allowRegexes: []
  };

  let clearDefaults = false;

  for (const line of lines) {
    const lower = line.toLowerCase();

    // 清空默认规则指令
    if (lower === '清空默认' || lower === 'clear') {
      clearDefaults = true;
      rules.keywords = [];
      rules.regexes = [];
      continue;
    }

    // 链接数量限制: max_links=N
    const maxLinksMatch = line.match(/max_links[=:](\d+)/i);
    if (maxLinksMatch) {
      rules.maxLinks = parseInt(maxLinksMatch[1]) || 0;
      continue;
    }

    // 放行关键词: allow:关键词1,关键词2
    if (lower.startsWith('allow:') || lower.startsWith('放行:')) {
      const content = line.split(/[:：]/, 2)[1] || '';
      const keywords = content.split(/[,，、]/).map(k => k.trim()).filter(Boolean);
      rules.allowKeywords.push(...keywords);
      continue;
    }

    // 拦截关键词: block:关键词1,关键词2
    if (lower.startsWith('block:') || lower.startsWith('拦截:') || lower.startsWith('屏蔽:')) {
      const content = line.split(/[:：]/, 2)[1] || '';
      const keywords = content.split(/[,，、]/).map(k => k.trim()).filter(Boolean);
      if (clearDefaults) {
        rules.keywords = keywords;
      } else {
        rules.keywords.push(...keywords);
      }
      continue;
    }

    // 放行正则: allow_re:正则
    if (lower.startsWith('allow_re:') || lower.startsWith('allow_regex:') || lower.startsWith('放行正则:')) {
      const content = line.split(/[:：]/, 2)[1] || '';
      if (content) rules.allowRegexes.push(content);
      continue;
    }

    // 拦截正则: block_re:正则
    if (lower.startsWith('block_re:') || lower.startsWith('block_regex:') || lower.startsWith('拦截正则:')) {
      const content = line.split(/[:：]/, 2)[1] || '';
      if (content) {
        if (clearDefaults) {
          rules.regexes = [content];
        } else {
          rules.regexes.push(content);
        }
      }
      continue;
    }

    // 裸行：作为关键词处理
    const keywords = line.split(/[,，、]/).map(k => k.trim()).filter(Boolean);
    if (clearDefaults) {
      rules.keywords = [...new Set([...rules.keywords, ...keywords])];
    } else {
      rules.keywords = [...new Set([...rules.keywords, ...keywords])];
    }
  }

  // 去重
  rules.keywords = [...new Set(rules.keywords)];
  rules.regexes = [...new Set(rules.regexes)];
  rules.allowKeywords = [...new Set(rules.allowKeywords)];
  rules.allowRegexes = [...new Set(rules.allowRegexes)];

  return rules;
}

// ========== 多级缓存系统优化 ==========

// L1 缓存：内存缓存（最快，进程内）
const memCache = new Map();
const MEMORY_CACHE_TTL = 30 * 60 * 1000; // 30 分钟
const BOT_SELF_CACHE_KEY = 'bot:self_profile';
const BOT_SELF_CACHE_TTL_MS = 10 * 60 * 1000;
const TOPIC_ENV_CACHE_KEY = 'topic_env_status';
const TOPIC_ENV_CACHE_TTL_MS = 5 * 60 * 1000;
const TOPIC_ENV_ALERT_CACHE_KEY = 'topic_env_alert';
const TOPIC_ENV_ALERT_COOLDOWN_MS = 10 * 60 * 1000;

// L2 缓存：KV 缓存（较慢，持久化）
const KV_CACHE_TTL = 60 * 60; // 1 小时

// 缓存统计
const cacheStats = {
  hits: 0,
  misses: 0,
  kvHits: 0,
  kvMisses: 0
};

/**
 * L1 缓存获取
 * @param {string} key - 缓存键
 * @returns {any} 缓存值
 */
function memGet(key) {
  const item = memCache.get(key);
  if (!item) {
    cacheStats.misses++;
    return undefined;
  }
  if (Date.now() > item.expiry) {
    memCache.delete(key);
    cacheStats.misses++;
    return undefined;
  }
  cacheStats.hits++;
  return item.value;
}

/**
 * L1 缓存设置
 * @param {string} key - 缓存键
 * @param {any} value - 缓存值
 * @param {number} ttlMs - 过期时间（毫秒）
 */
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

/**
 * L1 缓存删除
 * @param {string} key - 缓存键
 */
function memDelete(key) {
  memCache.delete(key);
}

/**
 * L2 缓存获取（KV 持久化）
 * @param {string} key - 缓存键
 * @param {any} defaultValue - 默认值
 * @returns {Promise<any>} 缓存值
 */
async function kvCacheGet(key, defaultValue = null) {
  try {
    const cached = await KV.get(key);
    if (cached) {
      cacheStats.kvHits++;
      return JSON.parse(cached);
    }
    cacheStats.kvMisses++;
    return defaultValue;
  } catch (e) {
    Logger.debug('kv_cache_get_error', e, { key });
    return defaultValue;
  }
}

/**
 * L2 缓存设置（KV 持久化）
 * @param {string} key - 缓存键
 * @param {any} value - 缓存值
 * @param {number} ttlSeconds - 过期时间（秒）
 */
async function kvCacheSet(key, value, ttlSeconds = KV_CACHE_TTL) {
  try {
    await KV.put(key, JSON.stringify(value), { expirationTtl: ttlSeconds });
  } catch (e) {
    Logger.debug('kv_cache_set_error', e, { key });
  }
}

/**
 * 多级缓存获取（L1 → L2）
 * @param {string} key - 缓存键
 * @param {Function} fetchFn - 获取数据的异步函数
 * @param {number} l1Ttl - L1 缓存 TTL（毫秒）
 * @param {number} l2Ttl - L2 缓存 TTL（秒）
 * @returns {Promise<any>} 缓存值
 */
async function multiLevelCacheGet(key, fetchFn, l1Ttl = MEMORY_CACHE_TTL, l2Ttl = KV_CACHE_TTL) {
  // 尝试 L1 缓存
  let value = memGet(key);
  if (value !== undefined) {
    return value;
  }

  // 尝试 L2 缓存
  value = await kvCacheGet(key);
  if (value !== null) {
    // 回填 L1 缓存
    memSet(key, value, l1Ttl);
    return value;
  }

  // 缓存未命中，调用 fetchFn 获取
  value = await fetchFn();

  // 同时写入 L1 和 L2 缓存
  memSet(key, value, l1Ttl);
  await kvCacheSet(key, value, l2Ttl);

  return value;
}

/**
 * 获取缓存统计信息
 * @returns {object} 缓存统计
 */
function getCacheStats() {
  const total = cacheStats.hits + cacheStats.misses;
  const hitRate = total > 0 ? ((cacheStats.hits / total) * 100).toFixed(2) : 0;
  const kvTotal = cacheStats.kvHits + cacheStats.kvMisses;
  const kvHitRate = kvTotal > 0 ? ((cacheStats.kvHits / kvTotal) * 100).toFixed(2) : 0;

  return {
    l1: {
      hits: cacheStats.hits,
      misses: cacheStats.misses,
      hitRate: hitRate + '%',
      size: memCache.size
    },
    l2: {
      hits: cacheStats.kvHits,
      misses: cacheStats.kvMisses,
      hitRate: kvHitRate + '%'
    }
  };
}

/**
 * 清空所有缓存
 */
function clearAllCache() {
  memCache.clear();
  cacheStats.hits = 0;
  cacheStats.misses = 0;
  cacheStats.kvHits = 0;
  cacheStats.kvMisses = 0;
}

// ========== KV 配额熔断保护 ==========

// 检查是否为 KV 配额错误
function isKvQuotaError(err) {
  if (!err) return false;
  const msg = String(err.message || err).toLowerCase();
  const status = err.status || 0;

  return status === 429 ||
    msg.includes("kv put failed: 429") ||
    msg.includes("kv get failed: 429") ||
    msg.includes("kv list failed: 429") ||
    (msg.includes("429") && (msg.includes("too many requests") || msg.includes("rate") || msg.includes("quota") || msg.includes("limit")));
}

// 触发熔断器
async function tripKvQuotaBreaker() {
  await KV.put(CONFIG.KV_QUOTA_BREAKER_KEY, "1", { expirationTtl: CONFIG.KV_QUOTA_BREAKER_TTL });
  Logger.warn('kv_quota_breaker_tripped', { ttl: CONFIG.KV_QUOTA_BREAKER_TTL });
}

// 检查熔断器是否触发
async function isKvQuotaBreakerTripped() {
  const v = await KV.get(CONFIG.KV_QUOTA_BREAKER_KEY);
  return v === "1";
}

// 检查是否应该发送 KV 配额超限通知
async function shouldSendKvQuotaNotice() {
  const key = `kv_quota_notice:${ADMIN_UID}`;
  const lastNotice = await KV.get(key);
  if (lastNotice) return false;
  await KV.put(key, "1", { expirationTtl: CONFIG.KV_QUOTA_NOTICE_COOLDOWN });
  return true;
}

// 发送 KV 配额超限通知
async function sendKvQuotaExceededNotice() {
  if (!(await shouldSendKvQuotaNotice())) return;
  try {
    await sendMessage({
      chat_id: ADMIN_UID,
      text: '⚠️ <b>KV 配额超限</b>\n\nCloudflare KV 操作被限制（429），已自动暂停 KV 操作。\n请稍后重试，或检查 Cloudflare 后台的 KV 用量。',
      parse_mode: 'HTML'
    });
  } catch (e) {
    Logger.error('kv_quota_notice_send_failed', e);
  }
}

// 安全的 KV 操作包装（带熔断保护）
async function safeKvGet(key) {
  if (await isKvQuotaBreakerTripped()) {
    throw new Error('KV quota breaker is tripped');
  }
  try {
    return await KV.get(key);
  } catch (e) {
    if (isKvQuotaError(e)) {
      await tripKvQuotaBreaker();
      await sendKvQuotaExceededNotice();
    }
    throw e;
  }
}

async function safeKvPut(key, value, options = {}) {
  if (await isKvQuotaBreakerTripped()) {
    throw new Error('KV quota breaker is tripped');
  }
  try {
    return await KV.put(key, value, options);
  } catch (e) {
    if (isKvQuotaError(e)) {
      await tripKvQuotaBreaker();
      await sendKvQuotaExceededNotice();
    }
    throw e;
  }
}

async function safeKvDelete(key) {
  if (await isKvQuotaBreakerTripped()) {
    throw new Error('KV quota breaker is tripped');
  }
  try {
    return await KV.delete(key);
  } catch (e) {
    if (isKvQuotaError(e)) {
      await tripKvQuotaBreaker();
      await sendKvQuotaExceededNotice();
    }
    throw e;
  }
}

// ========== 消息暂存队列 ==========

// 获取暂存队列 key
function pendingQueueKey(userId) {
  return `pending_queue:${userId}`;
}

// 获取用户的暂存消息队列
async function getPendingQueue(userId) {
  try {
    const data = await KV.get(pendingQueueKey(userId));
    if (!data) return [];
    const arr = JSON.parse(data);
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    Logger.error('get_pending_queue_failed', e, { userId });
    return [];
  }
}

// 添加消息到暂存队列（带去重）
async function appendPendingQueue(userId, messageId) {
  const mid = Number(messageId);
  if (!Number.isFinite(mid) || mid <= 0) return await getPendingQueue(userId);

  // 【优化】使用 safeGetJSON 安全读取
  let arr = await safeGetJSON(pendingQueueKey(userId), []);
  if (!Array.isArray(arr)) arr = [];

  // 【优化】去重检查：避免同一消息重复添加
  if (arr.includes(mid)) {
    Logger.debug('duplicate_message_skipped', { userId, messageId: mid });
    return arr;
  }

  arr.push(mid);

  // 【优化】保持顺序并限制队列长度（保留最新的）
  if (arr.length > CONFIG.PENDING_MAX_MESSAGES) {
    arr = arr.slice(-CONFIG.PENDING_MAX_MESSAGES);
  }

  try {
    await KV.put(pendingQueueKey(userId), JSON.stringify(arr), {
      expirationTtl: CONFIG.PENDING_QUEUE_TTL_SECONDS
    });
  } catch (e) {
    Logger.error('append_pending_queue_failed', e, { userId, messageId });
  }

  return arr;
}

// 清空暂存队列
async function clearPendingQueue(userId) {
  try {
    await KV.delete(pendingQueueKey(userId));
  } catch (e) {
    Logger.error('clear_pending_queue_failed', e, { userId });
  }
}

// 验证通过后处理暂存消息
async function processPendingMessagesAfterVerification(userId) {
  // 【优化】使用 safeGetJSON 安全读取
  const pendingIds = await safeGetJSON(pendingQueueKey(userId), []);

  if (!Array.isArray(pendingIds) || pendingIds.length === 0) {
    return { forwarded: 0, failed: 0 };
  }

  Logger.info('processing_pending_messages', { userId, count: pendingIds.length });

  let forwarded = 0;
  let failed = 0;
  const failedMessages = [];

  // 【优化】去重并排序，保持消息顺序
  const uniqueIds = [...new Set(pendingIds)];
  const sortedIds = uniqueIds.sort((a, b) => a - b);

  const topicEnabled = await isTopicForwardingEnabled();
  let topicContext = null;
  if (topicEnabled) {
    topicContext = await ensureUserTopic(userId, await getUserProfile(userId));
  }

  const targetForPending = topicContext && topicContext.threadId
    ? { chatId: GROUP_ID, threadId: topicContext.threadId, label: 'topic' }
    : { chatId: ADMIN_UID, label: 'admin_dm' };

  // 【优化】批量处理，添加小延迟避免触发限制
  for (let i = 0; i < sortedIds.length; i++) {
    const msgId = sortedIds[i];
    try {
      // 尝试转发消息（通过复制方式）
      const payload = {
        chat_id: targetForPending.chatId,
        from_chat_id: userId,
        message_id: msgId
      };
      if (targetForPending.threadId) {
        payload.message_thread_id = targetForPending.threadId;
      }

      const result = await forwardMessage(payload);

      if (result.ok && result.result && result.result.message_id) {
        forwarded++;
        await storeForwardMapping(
          result.result.message_id,
          { chat: { id: userId }, message_id: msgId },
          targetForPending
        );
      } else if (result.ok) {
        forwarded++;
      } else {
        // 【优化】区分错误类型：消息不存在 vs 其他错误
        if (result.description && result.description.includes('message to forward not found')) {
          Logger.warn('pending_message_not_found', { userId, messageId: msgId });
          // 消息不存在，视为成功（不需要重试）
        } else {
          failed++;
          failedMessages.push(msgId);
        }
      }
    } catch (e) {
      Logger.error('forward_pending_message_failed', e, { userId, messageId: msgId });
      failed++;
      failedMessages.push(msgId);
    }

    // 【优化】每5条消息添加小延迟，避免触发限制
    if ((i + 1) % 5 === 0 && i < sortedIds.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  // 【优化】清空已处理的队列
  if (failedMessages.length === 0) {
    await clearPendingQueue(userId);
  } else {
    // 保留失败的消息，下次重试
    try {
      await KV.put(pendingQueueKey(userId), JSON.stringify(failedMessages), {
        expirationTtl: CONFIG.PENDING_QUEUE_TTL_SECONDS
      });
      Logger.info('pending_messages_partially_failed', { userId, failedCount: failedMessages.length });
    } catch (e) {
      Logger.error('save_failed_pending_messages_failed', e, { userId });
    }
  }

  // 【修复】不再在此处通知用户，由调用方统一处理，避免重复通知
  // 通知用户的功能已移至验证成功后的代码中

  Logger.info('pending_messages_processed', { userId, forwarded, failed });
  return { forwarded, failed };
}

// ========== 用户资料缓存 ==========

// 用户资料缓存 key
function userProfileKey(userId) {
  return `user_profile:${userId}`;
}

// 用户资料更新冷却 key
function userProfileCooldownKey(userId) {
  return `profile:cooldown:${userId}`;
}

// 从 Telegram Update 中提取并缓存用户资料
async function upsertUserProfileFromUpdate(user) {
  try {
    if (!user || !user.id) return null;

    const userId = user.id.toString();

    // 检查冷却期
    const cooldownKey = userProfileCooldownKey(userId);
    const cooldown = await KV.get(cooldownKey);
    if (cooldown) return null; // 冷却期内不更新

    // 构建用户资料
    const profile = {
      id: userId,
      username: user.username || null,
      first_name: user.first_name || '',
      last_name: user.last_name || '',
      updated_at: Date.now()
    };

    // 保存到 KV
    await KV.put(userProfileKey(userId), JSON.stringify(profile), {
      expirationTtl: CONFIG.USER_PROFILE_CACHE_TTL
    });

    // 设置冷却期
    await KV.put(cooldownKey, "1", { expirationTtl: CONFIG.USER_PROFILE_COOLDOWN });

    Logger.debug('user_profile_cached', { userId, username: profile.username });
    return profile;
  } catch (e) {
    Logger.error('upsert_user_profile_failed', e, { userId: user?.id });
    return null;
  }
}

// 获取用户资料
async function getUserProfile(userId) {
  try {
    const data = await KV.get(userProfileKey(userId));
    if (!data) return null;
    return JSON.parse(data);
  } catch (e) {
    Logger.error('get_user_profile_failed', e, { userId });
    return null;
  }
}

// 获取用户显示名称（优先使用缓存的资料）
async function getUserDisplayName(userId) {
  // 1. 尝试从缓存获取
  const profile = await getUserProfile(userId);
  if (profile) {
    if (profile.first_name || profile.last_name) {
      return `${profile.first_name || ''} ${profile.last_name || ''}`.trim();
    }
    if (profile.username) {
      return `@${profile.username}`;
    }
  }

  // 2. 回退到已验证用户列表中的名称
  const verifiedName = await KV.get('verified-' + userId);
  if (verifiedName && verifiedName !== 'true') {
    return verifiedName;
  }

  return 'Unknown';
}

// 检查用户是否已验证（优先使用内存缓存，带重试机制）
async function isUserVerified(userId) {
  const verifiedKey = 'verified-' + userId;

  // 1. 先检查内存缓存
  const memVerified = memGet(verifiedKey);
  if (memVerified !== undefined) {
    return memVerified === "true";
  }

  // 2. 检查 KV（带重试机制，解决最终一致性延迟问题）
  const maxRetries = 3;
  const retryDelay = 1500; // 1.5秒

  for (let i = 0; i < maxRetries; i++) {
    const kvVerified = await KV.get(verifiedKey);
    if (kvVerified === 'true') {
      // 更新内存缓存
      memSet(verifiedKey, 'true', 5 * 60 * 1000);
      return true;
    }

    // 如果不是最后一次尝试，等待后重试
    if (i < maxRetries - 1) {
      await new Promise(r => setTimeout(r, retryDelay));
    }
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

// ========== 管理员权限缓存 ==========
const adminCache = new Map();
const ADMIN_CACHE_TTL_MS = 5 * 60 * 1000; // 5分钟缓存

/**
 * 检查用户是否为管理员
 * 支持主管理员和额外管理员列表
 * @param {string} userId - 用户ID
 * @returns {boolean} 是否为管理员
 */
function isAdmin(userId) {
  // 检查主管理员和环境变量中的管理员
  if (ADMIN_ALLOWLIST.has(String(userId))) {
    return true;
  }

  // 检查缓存
  const cached = adminCache.get(userId);
  if (cached && (Date.now() - cached.ts < ADMIN_CACHE_TTL_MS)) {
    return cached.isAdmin;
  }

  // 未缓存或已过期，需要异步检查（返回 false，异步更新缓存）
  checkAdminStatus(userId).catch(() => { });
  return false;
}

/**
 * 异步检查管理员状态并缓存
 * @param {string} userId - 用户ID
 * @returns {Promise<boolean>}
 */
async function checkAdminStatus(userId) {
  // 检查额外管理员列表（可以从 KV 读取）
  try {
    const extraAdmins = await KV.get('extra_admins');
    if (extraAdmins) {
      const adminList = extraAdmins.split(',').map(id => id.trim());
      const isExtraAdmin = adminList.includes(String(userId));

      // 更新缓存
      adminCache.set(userId, {
        isAdmin: isExtraAdmin,
        ts: Date.now()
      });

      return isExtraAdmin;
    }
  } catch (e) {
    Logger.error('check_admin_status_failed', e, { userId });
  }

  // 默认不是管理员
  adminCache.set(userId, {
    isAdmin: false,
    ts: Date.now()
  });

  return false;
}

/**
 * 强制刷新管理员缓存
 * @param {string} userId - 用户ID
 */
function clearAdminCache(userId) {
  if (userId) {
    adminCache.delete(userId);
  } else {
    adminCache.clear();
  }
}

// 防刷屏限流器（支持多类型）
const rateLimitCache = new Map();

/**
 * 精细化速率限制检查
 * @param {string} userId - 用户ID
 * @param {string} type - 限制类型: 'message' | 'verify' | 'verifyAttempt'
 * @returns {object} { allowed: boolean, remaining: number, retryAfter?: number }
 */
function checkRateLimit(userId, type = 'message') {
  const config = RATE_LIMIT_CONFIG[type];
  if (!config) {
    Logger.warn('unknown_rate_limit_type', { type });
    return { allowed: true, remaining: 999, limit: 999 };
  }

  const now = Date.now();
  const key = `${config.keyPrefix}:${userId}`;
  let userData = rateLimitCache.get(key);

  // 动态调整限额
  let adjustedMaxRequests = config.maxRequests;
  if (RATE_LIMIT_ENHANCED.enabledDynamicLimit) {
    // 检查用户是否为信任用户
    const isTrusted = memGet(`trusted:${userId}`);
    if (isTrusted) {
      adjustedMaxRequests = Math.floor(
        config.maxRequests * RATE_LIMIT_ENHANCED.trustedUserMultiplier
      );
    }
  }

  if (!userData) {
    userData = { count: 1, firstRequest: now, violations: 0 };
    rateLimitCache.set(key, userData);
    return { allowed: true, remaining: adjustedMaxRequests - 1, limit: adjustedMaxRequests };
  }

  // 检查是否在时间窗口内
  if (now - userData.firstRequest > config.windowMs) {
    // 重置窗口
    userData.count = 1;
    userData.firstRequest = now;
    userData.violations = 0;
    rateLimitCache.set(key, userData);
    return { allowed: true, remaining: adjustedMaxRequests - 1, limit: adjustedMaxRequests };
  }

  // 在窗口内，检查次数
  if (userData.count >= adjustedMaxRequests) {
    const retryAfter = Math.ceil((config.windowMs - (now - userData.firstRequest)) / 1000);
    userData.violations = (userData.violations || 0) + 1;

    // 记录违规次数（用于分级限流）
    if (userData.violations >= RATE_LIMIT_ENHANCED.maxPenaltyCount) {
      Logger.warn('rate_limit_violation_excessive', {
        userId,
        type,
        violations: userData.violations,
        retryAfter
      });
    }

    return {
      allowed: false,
      retryAfter,
      limit: adjustedMaxRequests,
      violations: userData.violations
    };
  }

  userData.count++;
  return {
    allowed: true,
    remaining: adjustedMaxRequests - userData.count,
    limit: adjustedMaxRequests
  };
}

/**
 * 检查验证请求频率限制（KV 持久化，跨实例生效）
 * @param {string} userId - 用户ID
 * @param {string} type - 限制类型
 * @returns {Promise<object>} 速率限制结果
 */
async function checkRateLimitKV(userId, type = 'verify') {
  const config = RATE_LIMIT_CONFIG[type];
  if (!config) {
    return { allowed: true, remaining: 999 };
  }

  const key = `${config.keyPrefix}:${userId}`;
  const now = Date.now();
  const windowMs = config.windowMs;

  // 使用 safeGetJSON 获取历史记录
  let timestamps = await safeGetJSON(key, []);
  if (!Array.isArray(timestamps)) timestamps = [];

  // 过滤掉过期的记录
  timestamps = timestamps.filter(ts => (now - ts) < windowMs);

  if (timestamps.length >= config.maxRequests) {
    const oldestTimestamp = timestamps[0];
    const retryAfter = Math.ceil((windowMs - (now - oldestTimestamp)) / 1000);
    return { allowed: false, retryAfter, limit: config.maxRequests };
  }

  // 添加新记录
  timestamps.push(now);
  await KV.put(key, JSON.stringify(timestamps), {
    expirationTtl: Math.ceil(windowMs / 1000) + 60
  });

  return { allowed: true, remaining: config.maxRequests - timestamps.length };
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
    Logger.error('add_verified_user_failed', e, { userId });
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
    Logger.error('remove_verified_user_failed', e, { userId });
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
    Logger.error('get_verified_users_failed', e);
    return [];
  }
}

// 配置管理
const CONFIG_KEYS = {
  WELCOME_MSG: 'config:welcome_msg',
  AUTO_REPLY_MSG: 'config:auto_reply_msg',
  VERIFY_TTL: 'config:verify_ttl',
  UNION_BAN: 'config:union_ban',
  FORWARD_MODE: 'config:forward_mode'
};

const FORWARD_MODES = {
  DIRECT: 'direct',
  TOPIC: 'topic'
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

async function getForwardMode() {
  const mode = await getConfig(CONFIG_KEYS.FORWARD_MODE, FORWARD_MODES.DIRECT);
  return mode === FORWARD_MODES.TOPIC ? FORWARD_MODES.TOPIC : FORWARD_MODES.DIRECT;
}

async function setForwardMode(mode) {
  const next = mode === FORWARD_MODES.TOPIC ? FORWARD_MODES.TOPIC : FORWARD_MODES.DIRECT;
  await setConfig(CONFIG_KEYS.FORWARD_MODE, next);
  return next;
}

function hasTopicForwardingPrerequisites() {
  return Boolean(GROUP_ID && ADMIN_UID);
}

async function getBotSelfProfile(force = false) {
  const cached = memGet(BOT_SELF_CACHE_KEY);
  if (cached && !force) return cached;

  const result = await requestTelegram('getMe', {});
  if (!result.ok || !result.result) {
    throw new Error(result.description || 'getMe_failed');
  }
  memSet(BOT_SELF_CACHE_KEY, result.result, BOT_SELF_CACHE_TTL_MS);
  return result.result;
}

async function performTopicEnvironmentCheck() {
  if (!GROUP_ID) {
    return { ok: false, reason: 'group_missing' };
  }
  try {
    const chatInfo = await requestTelegram('getChat', { chat_id: GROUP_ID });
    if (!chatInfo.ok) {
      return { ok: false, reason: 'chat_inaccessible', description: chatInfo.description };
    }
    if (!chatInfo.result || chatInfo.result.is_forum === false) {
      return { ok: false, reason: 'not_forum' };
    }

    const botProfile = await getBotSelfProfile();
    const memberInfo = await requestTelegram('getChatMember', { chat_id: GROUP_ID, user_id: botProfile.id });
    if (!memberInfo.ok) {
      return { ok: false, reason: 'membership', description: memberInfo.description };
    }
    const rights = memberInfo.result;
    if (rights.status !== 'administrator') {
      return { ok: false, reason: 'not_admin' };
    }
    if (!rights.can_manage_topics) {
      return { ok: false, reason: 'missing_manage_topics' };
    }
    return { ok: true };
  } catch (e) {
    Logger.error('topic_env_check_failed', e);
    return { ok: false, reason: 'unknown', description: e.message };
  }
}

async function verifyTopicEnvironment(options = {}) {
  const { force = false, notifyOnFailure = true } = options;
  if (!GROUP_ID) {
    return { ok: false, reason: 'group_missing' };
  }

  if (!force) {
    const cached = memGet(TOPIC_ENV_CACHE_KEY);
    if (cached) return cached;
  }

  const status = await performTopicEnvironmentCheck();
  memSet(TOPIC_ENV_CACHE_KEY, status, TOPIC_ENV_CACHE_TTL_MS);

  if (!status.ok && notifyOnFailure) {
    await maybeNotifyTopicEnvIssue(status);
  }
  return status;
}

function describeTopicEnvIssue(status) {
  switch (status.reason) {
    case 'group_missing':
      return 'GROUP_ID is not configured.';
    case 'chat_inaccessible':
      return `bot cannot access the configured group (${status.description || 'unknown error'}).`;
    case 'not_forum':
      return 'the target group has not enabled Topics.';
    case 'not_admin':
      return 'the bot is not an administrator in the group.';
    case 'missing_manage_topics':
      return 'the bot is missing the Manage Topics permission.';
    case 'membership':
      return `unable to read bot permissions: ${status.description || 'unknown error'}.`;
    default:
      return status.description || 'unexpected error while checking the forum group.';
  }
}

async function maybeNotifyTopicEnvIssue(status) {
  if (!ADMIN_UID) return;
  const last = memGet(TOPIC_ENV_ALERT_CACHE_KEY);
  if (last && Date.now() - last < TOPIC_ENV_ALERT_COOLDOWN_MS) return;

  memSet(TOPIC_ENV_ALERT_CACHE_KEY, Date.now(), TOPIC_ENV_ALERT_COOLDOWN_MS);
  const text = `[Notice] Topic mode is unavailable: ${describeTopicEnvIssue(status)}`;
  try {
    await sendMessage({
      chat_id: ADMIN_UID,
      text
    });
  } catch (e) {
    Logger.warn('topic_env_notice_failed', e);
  }
}

async function isTopicForwardingEnabled() {
  if (!hasTopicForwardingPrerequisites()) return false;
  const mode = await getForwardMode();
  return mode === FORWARD_MODES.TOPIC;
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
    Logger.error('report_error_failed', e);
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
    Logger.error('increment_message_count_failed', e);
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
    Logger.error('record_active_user_failed', e);
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
    Logger.error('get_stats_failed', e);
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

// Telegram API 基础 URL（可配置，用于代理场景）
let API_BASE = 'https://api.telegram.org';

/**
 * 设置自定义 API 基础 URL
 * @param {string} baseUrl - API 基础 URL
 */
function setApiBase(baseUrl) {
  if (baseUrl && typeof baseUrl === 'string') {
    // 【安全】强制 HTTPS
    if (baseUrl.startsWith('http://')) {
      Logger.warn('api_http_upgraded', { originalBase: baseUrl });
      baseUrl = baseUrl.replace('http://', 'https://');
    }
    // 验证 URL 格式
    try {
      new URL(baseUrl);
      API_BASE = baseUrl;
    } catch (e) {
      Logger.error('invalid_api_base', e, { baseUrl });
    }
  }
}

function apiUrl(methodName, params = null) {
  let query = '';
  if (params) {
    query = '?' + new URLSearchParams(params).toString();
  }
  return `${API_BASE}/bot${TOKEN}/${methodName}${query}`;
}

/**
 * Telegram API 错误分类
 * @param {string} description - 错误描述
 * @returns {string} 错误类型
 */
function classifyTelegramError(description) {
  if (!description) return 'unknown';
  const desc = description.toLowerCase();

  // 消息相关错误
  if (desc.includes('message thread not found') || desc.includes('topic not found')) {
    return 'thread_not_found';
  }
  if (desc.includes('message to forward not found') || desc.includes('message not found')) {
    return 'message_not_found';
  }
  if (desc.includes('message text is empty') || desc.includes('message is empty')) {
    return 'empty_message';
  }
  if (desc.includes('message is too long') || desc.includes('text is too long')) {
    return 'message_too_long';
  }

  // 用户相关错误
  if (desc.includes('chat not found') || desc.includes('user not found')) {
    return 'chat_not_found';
  }
  if (desc.includes('bot was blocked') || desc.includes('blocked by user')) {
    return 'bot_blocked';
  }
  if (desc.includes('user is deactivated')) {
    return 'user_deactivated';
  }

  // 权限错误
  if (desc.includes('not enough rights') || desc.includes('forbidden')) {
    return 'permission_denied';
  }

  // 速率限制
  if (desc.includes('too many requests') || desc.includes('retry after')) {
    return 'rate_limited';
  }

  // 网络错误
  if (desc.includes('network') || desc.includes('timeout') || desc.includes('fetch')) {
    return 'network_error';
  }

  // 验证错误
  if (desc.includes('unauthorized') || desc.includes('invalid token')) {
    return 'auth_error';
  }

  return 'unknown';
}

/**
 * 获取用户友好的错误消息
 * @param {string} errorType - 错误类型
 * @param {string} defaultMsg - 默认消息
 * @returns {string} 用户友好消息
 */
function getUserFriendlyErrorMessage(errorType, defaultMsg = '操作失败') {
  const messages = {
    message_not_found: '消息不存在或已过期',
    empty_message: '消息内容不能为空',
    message_too_long: '消息内容过长',
    chat_not_found: '聊天不存在',
    bot_blocked: '您已屏蔽机器人，请解除屏蔽后重试',
    user_deactivated: '用户账号已注销',
    permission_denied: '权限不足',
    rate_limited: '操作过于频繁，请稍后再试',
    network_error: '网络错误，请稍后重试',
    auth_error: '认证失败，请检查配置',
    timeout: '请求超时，请稍后重试',
    unknown: defaultMsg
  };
  return messages[errorType] || defaultMsg;
}

async function requestTelegram(methodName, body, params = null, timeout = CONFIG.API_TIMEOUT_MS) {
  // 【安全改进】添加超时控制
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const resp = await fetch(apiUrl(methodName, params), {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    // 记录服务器错误
    if (!resp.ok && resp.status >= 500) {
      Logger.warn('telegram_api_server_error', { method: methodName, status: resp.status });
    }

    const result = await resp.json();

    // 【优化】错误分类处理
    if (!result.ok && result.description) {
      const errorType = classifyTelegramError(result.description);
      result.errorType = errorType;
      result.userMessage = getUserFriendlyErrorMessage(errorType);

      // 记录特定错误类型
      if (errorType === 'rate_limited') {
        const retryAfter = result.parameters?.retry_after || 5;
        Logger.warn('telegram_api_rate_limit', { method: methodName, retryAfter });
      } else if (errorType === 'bot_blocked') {
        Logger.info('bot_blocked_by_user', { method: methodName, chatId: body?.chat_id });
      } else if (errorType !== 'unknown') {
        Logger.warn('telegram_api_error', { method: methodName, errorType, description: result.description });
      }
    }

    return result;
  } catch (e) {
    clearTimeout(timeoutId);

    if (e.name === 'AbortError') {
      Logger.error('telegram_api_timeout', e, { method: methodName, timeout });
      return {
        ok: false,
        description: 'Request timeout',
        errorType: 'timeout',
        userMessage: getUserFriendlyErrorMessage('timeout')
      };
    }

    Logger.error('telegram_api_failed', e, { method: methodName });
    return {
      ok: false,
      description: e.message,
      errorType: 'network_error',
      userMessage: getUserFriendlyErrorMessage('network_error')
    };
  }
}

function sendMessage(msg = {}) {
  return requestTelegram('sendMessage', msg);
}

function copyMessage(msg = {}) {
  return requestTelegram('copyMessage', msg);
}

async function forwardMessage(msg = {}) {
  const result = await requestTelegram('forwardMessage', msg);
  if (shouldFallbackToCopy(result)) {
    return requestTelegram('copyMessage', msg);
  }
  return result;
}

async function forwardMessagesWithFallback(msg = {}) {
  const result = await requestTelegram('forwardMessages', msg);
  if (shouldFallbackToCopy(result)) {
    return requestTelegram('copyMessages', msg);
  }
  return result;
}

function shouldFallbackToCopy(result) {
  if (!result || result.ok) return false;
  if (result.errorType === 'message_not_found') return true;
  const desc = (result.description || '').toLowerCase();
  return desc.includes('message to forward not found') || desc.includes('content private');
}

// 设置 Telegram 命令列表
async function setBotCommands() {
  const adminCommands = [
    { command: 'help', description: '显示帮助' },
    { command: 'menu', description: '管理菜单' },
    { command: 'ban', description: '封禁用户' },
    { command: 'unban', description: '解除封禁' },
    { command: 'reset', description: '重置验证' },
    { command: 'trust', description: '信任用户' },
    { command: 'untrust', description: '取消信任' },
    { command: 'broadcast', description: '广播消息' },
    { command: 'bcancel', description: '取消广播' },
    { command: 'welcome', description: '欢迎消息' },
    { command: 'autoreply', description: '自动回复' }
  ];

  try {
    // 为管理员设置命令列表
    const adminTargets = ADMIN_ID_LIST.length ? ADMIN_ID_LIST : (ADMIN_UID ? [ADMIN_UID] : []);
    for (const adminId of adminTargets) {
      await requestTelegram('setMyCommands', {
        commands: adminCommands,
        scope: { type: 'chat', chat_id: adminId }
      });
    }
    Logger.info('admin_commands_set');
  } catch (e) {
    Logger.error('set_admin_commands_failed', e);
  }
}

/**
 * 验证环境变量配置
 * @returns {object} { valid: boolean, error?: string, missing?: string[] }
 */
function validateEnvironment() {
  const missing = [];
  const invalid = [];

  // 检查必需变量
  if (!TOKEN) missing.push('ENV_BOT_TOKEN');
  if (!SECRET) missing.push('ENV_BOT_SECRET');
  if (!ADMIN_ID_LIST.length) missing.push('ENV_ADMIN_UID 或 ADMIN_IDS');

  if (missing.length > 0) {
    return {
      valid: false,
      error: 'Missing required environment variables',
      missing
    };
  }

  // 验证 BOT_TOKEN 格式（应该包含冒号）
  if (!TOKEN.includes(':')) {
    invalid.push('ENV_BOT_TOKEN (should be in format: 123456:ABC-DEF...)');
  }

  // 验证 ADMIN_UID 是否为数字
  if (RAW_ADMIN_UID && !/^-?\d+$/.test(String(RAW_ADMIN_UID))) {
    invalid.push('ENV_ADMIN_UID (should be a numeric ID)');
  }

  if (ADMIN_IDS_ENV) {
    const rawIds = ADMIN_IDS_ENV.split(/[,;\s]+/).map(s => s.trim()).filter(Boolean);
    const invalidIds = rawIds.filter(id => !/^-?\d+$/.test(id));
    if (invalidIds.length) {
      invalid.push('ADMIN_IDS (all entries must be numeric Telegram user IDs)');
    }
  }

  // 验证 SECRET 长度（建议至少 16 个字符）
  if (String(SECRET).length < 16) {
    invalid.push('ENV_BOT_SECRET (should be at least 16 characters for security)');
  }

  if (invalid.length > 0) {
    return {
      valid: false,
      error: 'Invalid environment variable format',
      missing: invalid
    };
  }

  return { valid: true };
}

addEventListener('fetch', event => {
  // 【优化】完善环境变量类型检查
  const envCheck = validateEnvironment();
  if (!envCheck.valid) {
    event.respondWith(new Response(
      `Error: ${envCheck.error}\n\n` +
      `Missing variables: ${envCheck.missing.join(', ')}\n\n` +
      `Please set these variables in Cloudflare Dashboard:\n` +
      `Workers & Pages → Your Worker → Settings → Variables`,
      { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    ));
    return;
  }

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
  const update = await event.request.json();
  event.waitUntil(onUpdate(update, url.origin));
  return new Response('Ok');
}

async function onUpdate(update, origin) {
  if ('callback_query' in update) {
    const callbackQuery = update.callback_query;
    const userId = String(callbackQuery.from.id);

    // 处理本地题库验证回调（普通用户）
    if (callbackQuery.data && callbackQuery.data.startsWith('quiz_answer:')) {
      return handleQuizCallback(callbackQuery);
    }

    // 处理验证模式切换回调（管理员）
    if (isAdmin(userId) && callbackQuery.data && callbackQuery.data.startsWith('verify_mode:')) {
      return handleVerifyModeCallback(callbackQuery);
    }

    // 处理回调查询（管理面板按钮）
    if (isAdmin(userId)) {
      return handleAdminCallback(callbackQuery);
    }
  } else if ('message' in update) {
    await onMessage(update.message, origin);
  } else if ('edited_message' in update) {
    await onEditedMessage(update.edited_message, origin);
  }
}

async function onMessage(message, origin) {
  const chatId = message.chat.id.toString();
  const senderId = message.from ? String(message.from.id) : null;
  const isGroupAdminChat = GROUP_ID && chatId === GROUP_ID;

  // 缓存用户资料（从消息中）
  if (message.from) {
    await upsertUserProfileFromUpdate(message.from);
  }

  // 1. 如果是管理员发消息
  if (isAdmin(chatId) || (isGroupAdminChat && senderId && isAdmin(senderId))) {
    return handleAdminMessage(message);
  }

  // 2. 如果是访客 (普通用户)
  else {
    const text = (message.text || '').trim();

    // 【防骚扰】拦截普通用户发送的指令（除 /start 外）
    if (text.startsWith('/') && text !== '/start') {
      // 静默拦截，不返回任何提示
      Logger.debug('user_command_blocked', { userId: chatId, command: text.split(' ')[0] });
      return;
    }

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
      // 4. 检查垃圾消息过滤
      const spamCheck = await checkSpam(message, chatId);
      if (spamCheck.isSpam) {
        // 检查垃圾话题功能是否启用
        const spamTopicEnabled = await isSpamTopicEnabled();
        const spamTopicConfig = await getSpamTopicConfig();

        if (spamTopicEnabled && spamTopicConfig.topicId && GROUP_ID) {
          // 静默转发到垃圾话题
          const forwarded = await silentlyForwardSpamMessage(message, GROUP_ID, spamTopicConfig.topicId);
          if (forwarded) {
            // 用户无感知，不返回错误消息
            return sendMessage({
              chat_id: chatId,
              text: '✅ 消息已发送'  // 假装成功发送
            });
          }
        }

        // 传统模式：拦截并通知管理员
        // 记录垃圾消息
        await sendMessage({
          chat_id: ADMIN_UID,
          text: `🗑 <b>垃圾消息拦截</b>\n\nUID: <code>${chatId}</code>\n原因: ${spamCheck.reason}\n\n<i>消息已拦截，未转发给管理员</i>`,
          parse_mode: 'HTML'
        });
        return sendMessage({
          chat_id: chatId,
          text: '🚫 您的消息因违反规则被拦截。如有疑问请联系管理员。'
        });
      }

      // 5. 检查防刷屏限制（精细化速率限制）
      const rateLimit = checkRateLimit(chatId, 'message');
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
  if (isAdmin(chatId)) {
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
  const contextChatId = message.chat?.id ? String(message.chat.id) : null;

  // 【话题模式支持】如果消息来自话题，直接从话题 ID 获取用户 UID
  const isTopicMode = await isTopicForwardingEnabled();
  if (isTopicMode && contextChatId === GROUP_ID && message.message_thread_id) {
    const threadId = message.message_thread_id;
    const userId = await KV.get(`thread:${threadId}`);
    if (userId) {
      Logger.info('get_target_id_from_topic', { commandName, threadId, userId });
      return userId;
    }
  }

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

// 获取已验证用户列表（支持分页和过滤）
async function getVerifiedUsers(page = 1, pageSize = 10, filter = 'all') {
  // 获取所有已验证用户（会自动处理新旧版本迁移）
  const allUsers = await getAllVerifiedUsers();

  if (!allUsers || allUsers.length === 0) {
    return { users: [], total: 0, totalPages: 0 };
  }

  try {
    // 获取每个用户的详细信息并过滤
    const userDetails = [];
    for (const [userId, userName] of allUsers) {
      const blocked = await KV.get('blocked-' + userId);
      const whitelisted = await isWhitelisted(userId);

      const user = {
        id: userId,
        name: userName || 'Unknown',
        blocked: blocked === 'true',
        whitelisted: whitelisted
      };

      // 应用过滤
      if (filter === 'whitelisted' && !whitelisted) continue;
      if (filter === 'blocked' && !blocked) continue;

      userDetails.push(user);
    }

    const total = userDetails.length;
    const totalPages = Math.ceil(total / pageSize) || 1;

    // 确保页码有效
    page = Math.max(1, Math.min(page, totalPages));

    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    const users = userDetails.slice(start, end);

    return {
      users,
      total,
      page,
      totalPages,
      pageSize
    };
  } catch (e) {
    Logger.error('get_user_list_failed', e);
    return { users: [], total: 0, totalPages: 0 };
  }
}

// 生成主菜单
async function generateMainMenu() {
  const welcomeMsg = await getConfig(CONFIG_KEYS.WELCOME_MSG);
  const autoReplyMsg = await getConfig(CONFIG_KEYS.AUTO_REPLY_MSG);
  const unionBanEnabled = await getConfig(CONFIG_KEYS.UNION_BAN, '0');
  const verifyMode = await getVerifyMode();
  const spamFilterEnabled = await getSpamFilterEnabled();
  const aiConfig = await getAISpamDetectionConfig();
  const forwardMode = await getForwardMode();

  const welcomeStatus = welcomeMsg ? '🟢' : '⚪️';
  const autoReplyStatus = autoReplyMsg ? '🟢' : '⚪️';
  const unionBanStatus = (unionBanEnabled === '1' || unionBanEnabled === 'true') ? '🟢' : '🔴';
  const spamFilterStatus = spamFilterEnabled ? '🟢' : '🔴';
  const aiStatus = aiConfig.enabled ? '🟢' : '⚪️';
  const forwardStatus = forwardMode === FORWARD_MODES.TOPIC ? '💬 话题' : '📥 私聊';

  const text = `🛠 <b>SafeRelay 管理面板</b>

  📊 <b>当前配置:</b>
  🔸 验证模式：${getVerifyModeName(verifyMode)}
  🔸 垃圾过滤 ${spamFilterStatus}
  🔸 AI 检测 ${aiStatus}
  🔸 联合封禁 ${unionBanStatus}
  🔸 欢迎消息 ${welcomeStatus}
  🔸 自动回复 ${autoReplyStatus}
  🔸 转发模式 ${forwardStatus}

  👇 点击下方按钮进入设置`;

  const keyboard = {
    inline_keyboard: [
      [{ text: '🛡 验证模式', callback_data: 'submenu_verify' }, { text: '🗑 垃圾过滤', callback_data: 'submenu_spam' }],
      [{ text: '🤖 AI 检测', callback_data: 'submenu_ai' }, { text: '🗑 垃圾话题', callback_data: 'submenu_spamtopic' }],
      [{ text: '🌐 联合封禁', callback_data: 'submenu_union' }, { text: '👥 用户管理', callback_data: 'submenu_users' }],
      [{ text: '👋 欢迎消息', callback_data: 'submenu_welcome' }, { text: '🤖 自动回复', callback_data: 'submenu_autoreply' }],
      [{ text: '💬 转发模式', callback_data: 'submenu_forward' }],
      [{ text: '📊 统计信息', callback_data: 'submenu_stats' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成垃圾过滤子菜单
async function generateSpamFilterSubmenu() {
  const enabled = await getSpamFilterEnabled();
  const rules = await getSpamFilterRules();

  const text = `🗑 <b>垃圾消息过滤设置</b>

当前状态: <b>${enabled ? '🟢 已开启' : '🔴 已关闭'}</b>

<b>当前规则:</b>
${formatSpamRules(rules)}

<b>快捷操作:</b>
• 直接发送关键词添加拦截规则
• 发送 <code>清空默认</code> 清空所有默认规则
• 发送 <code>max_links:N</code> 设置链接限制
• 发送 <code>allow:关键词</code> 添加放行规则

💡 支持同时发送多行，每行一个规则`;

  const keyboard = {
    inline_keyboard: [
      [{ text: enabled ? '🔴 关闭过滤' : '🟢 开启过滤', callback_data: 'toggle_spam_filter' }],
      [{ text: '🔑 关键词管理', callback_data: 'manage_keywords' }],
      [{ text: '🔄 重置为默认规则', callback_data: 'reset_spam_rules' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成关键词管理子菜单
async function generateKeywordManagementSubmenu() {
  const rules = await getSpamFilterRules();
  const keywords = rules.keywords || [];
  const allowKeywords = rules.allowKeywords || [];
  const regexes = rules.regexes || [];
  const allowRegexes = rules.allowRegexes || [];

  const text = `🔑 <b>关键词规则管理</b>

<b>拦截关键词 (${keywords.length}个):</b>
${formatKeywordList(keywords, 10)}

<b>放行关键词 (${allowKeywords.length}个):</b>
${formatKeywordList(allowKeywords, 5)}

<b>拦截正则 (${regexes.length}个):</b>
${formatKeywordList(regexes, 3)}

<b>放行正则 (${allowRegexes.length}个):</b>
${formatKeywordList(allowRegexes, 3)}

<b>管理方法:</b>
• 添加拦截词：直接发送关键词
• 添加放行词：<code>allow:关键词</code>
• 添加正则：<code>regex:正则表达式</code>
• 删除拦截词：<code>del:关键词</code>
• 删除放行词：<code>delallow:关键词</code>
• 清空所有：<code>清空默认</code>

💡 关键词和正则会立即生效`;

  const keyboard = {
    inline_keyboard: [
      [{ text: '📋 查看完整列表', callback_data: 'view_all_keywords' }],
      [{ text: '🗑️ 清空拦截词', callback_data: 'clear_keywords' }],
      [{ text: '🔄 恢复默认规则', callback_data: 'reset_spam_rules' }],
      [{ text: '◀️ 返回过滤设置', callback_data: 'back_to_spam_filter' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 格式化关键词列表（用于显示）
function formatKeywordList(keywords, maxDisplay = 10) {
  if (!keywords || keywords.length === 0) {
    return '<i>(空)</i>';
  }

  const display = keywords.slice(0, maxDisplay);
  const text = display.map(k => `• <code>${escapeHtml(k)}</code>`).join('\n');

  if (keywords.length > maxDisplay) {
    return text + `\n... 还有 ${keywords.length - maxDisplay} 个`;
  }

  return text;
}

// 生成 AI 检测设置子菜单
async function generateAISpamSubmenu() {
  const aiConfig = await getAISpamDetectionConfig();
  const rateLimit = await checkAIRateLimit();

  const text = `🤖 <b>AI 垃圾检测设置</b>

当前状态：<b>${aiConfig.enabled ? '🟢 已开启' : '🔴 已关闭'}</b>

<b>配置信息:</b>
🔹 置信度阈值：${aiConfig.confidenceThreshold || 0.7}
🔹 每小时限额：${CONFIG.AI_RATE_LIMIT_PER_HOUR} 次
🔹 剩余次数：${rateLimit.remaining} 次
${!rateLimit.allowed ? `🔹 重置时间：${rateLimit.resetAfter} 秒后` : ''}

<b>使用说明:</b>
• AI 检测作为关键词过滤的补充
• 自动识别广告、推广、投资等垃圾内容
• 需要配置 Cloudflare Workers AI

<b>环境变量:</b>
<code>CF_ACCOUNT_ID</code> - Cloudflare Account ID
<code>CF_AI_TOKEN</code> - Cloudflare AI API Token

💡 建议：先使用关键词过滤，AI 作为兜底策略`;

  const keyboard = {
    inline_keyboard: [
      [{ text: aiConfig.enabled ? '🔴 关闭 AI 检测' : '🟢 开启 AI 检测', callback_data: 'toggle_ai_detection' }],
      [{ text: '⚙️ 调整置信度', callback_data: 'ai_confidence' }],
      [{ text: '📊 查看使用统计', callback_data: 'ai_stats' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成垃圾话题设置子菜单
async function generateSpamTopicSubmenu() {
  const config = await getSpamTopicConfig();
  const spamFilterEnabled = await getSpamFilterEnabled();
  const aiEnabled = await isAISpamDetectionEnabled();

  const text = `🗑 <b>垃圾话题管理设置</b>

当前状态：<b>${config.enabled ? '🟢 已开启' : '🔴 已关闭'}</b>

<b>配置信息:</b>
🔹 垃圾话题 ID: ${config.topicId || '(未设置)'}
🔹 自动创建：${config.autoCreate ? '✅' : '❌'}
🔹 管理员通知：${config.notifyAdmin ? '✅' : '❌'}

<b>关联功能:</b>
🔸 垃圾过滤：${spamFilterEnabled ? '🟢' : '🔴'}
🔸 AI 检测：${aiEnabled ? '🟢' : '🔴'}

<b>使用说明:</b>
• 垃圾话题用于隔离垃圾消息
• 可选择静默转发（用户无感知）
• 管理员可随时查看和恢复消息

<b>操作步骤:</b>
1. 配置群组 ID（论坛群组）
2. 点击"自动创建话题"或手动指定
3. 开启垃圾话题功能
4. 配合垃圾过滤和 AI 检测使用`;

  const keyboard = {
    inline_keyboard: [
      [{ text: config.enabled ? '🔴 关闭垃圾话题' : '🟢 开启垃圾话题', callback_data: 'toggle_spam_topic' }],
      [{ text: '🏗️ 自动创建话题', callback_data: 'create_spam_topic' }],
      [{ text: '⚙️ 配置话题 ID', callback_data: 'config_spam_topic_id' }],
      [{ text: '📊 查看垃圾消息', callback_data: 'view_spam_messages' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

async function generateForwardModeSubmenu() {
  const mode = await getForwardMode();
  const issues = [];
  if (!GROUP_ID) issues.push('• 未设置 GROUP_ID 环境变量');
  if (!ADMIN_UID) issues.push('• 未设置 ENV_ADMIN_UID（主管理员）');

  const text = `💬 <b>消息转发模式</b>

当前模式：<b>${mode === FORWARD_MODES.TOPIC ? '话题模式（论坛群组）' : '私聊模式（管理员私聊）'}</b>

<b>说明：</b>
• 私聊模式：所有消息只发到管理员私聊
• 话题模式：每个访客自动创建话题，消息转发到论坛群组

${issues.length ? '<b>启用话题模式前请完成：</b>\n' + issues.join('\n') : '✅ 话题模式条件已满足，可随时开启。'}

在话题模式下，请确保机器人是群组管理员并具备「管理话题」权限。`;

  const keyboard = {
    inline_keyboard: [
      [{ text: (mode === FORWARD_MODES.DIRECT ? '✅ ' : '') + '📥 私聊转发', callback_data: 'forward_mode:direct' }],
      [{ text: (mode === FORWARD_MODES.TOPIC ? '✅ ' : '') + '💬 话题转发', callback_data: 'forward_mode:topic' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 生成验证模式子菜单
async function generateVerifySubmenu() {
  const currentMode = await getVerifyMode();
  const turnstileAvailable = hasTurnstileConfigured();

  let text = `🛡 <b>验证模式设置</b>

当前模式: <b>${getVerifyModeName(currentMode)}</b>

<b>可选模式:</b>
📝 <b>本地题库</b> - 使用内置简单题目验证（默认，无需配置）
☁️ <b>Turnstile</b> - 使用 Cloudflare Turnstile 网页验证
🔒 <b>双重验证</b> - 需要同时通过两种验证

`;

  if (!turnstileAvailable) {
    text += `⚠️ <b>注意:</b> 未检测到 Turnstile 配置，只能使用本地题库验证。
请在环境变量中配置 CF_TURNSTILE_SITE_KEY 和 CF_TURNSTILE_SECRET_KEY 后使用其他模式。`;
  }

  const keyboard = {
    inline_keyboard: [
      [{ text: (currentMode === 'local_quiz' ? '✅ ' : '') + '📝 本地题库', callback_data: 'verify_mode:local_quiz' }],
      [{ text: (currentMode === 'turnstile' ? '✅ ' : '') + '☁️ Turnstile', callback_data: 'verify_mode:turnstile' }],
      [{ text: (currentMode === 'both' ? '✅ ' : '') + '🔒 双重验证', callback_data: 'verify_mode:both' }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
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
async function generateUsersSubmenu(page = 1, filter = 'all') {
  const result = await getVerifiedUsers(page, 10, filter);

  // 获取各类用户数量统计
  const stats = await getUserStats();

  if (result.total === 0) {
    const filterText = getFilterText(filter);
    const text = `👥 <b>用户管理</b> <code>${filterText}</code>

📊 全部 ${stats.total} | ⭐信任 ${stats.whitelisted} | 🚫拉黑 ${stats.blocked}

暂无${filterText}用户。`;

    // 过滤按钮（当前选中的显示为 ✅）
    const filterButtonsEmpty = [
      { text: (filter === 'all' ? '✅ ' : '') + '👁 全部', callback_data: 'users_filter:all' },
      { text: (filter === 'whitelisted' ? '✅ ' : '') + '⭐ 信任', callback_data: 'users_filter:whitelisted' },
      { text: (filter === 'blocked' ? '✅ ' : '') + '🚫 拉黑', callback_data: 'users_filter:blocked' }
    ];

    const keyboard = {
      inline_keyboard: [
        filterButtonsEmpty,
        [{ text: '🔄 刷新', callback_data: `refresh_users:${page}:${filter}` }],
        [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
      ]
    };

    return { text, reply_markup: keyboard };
  }

  // 构建用户列表（使用缓存的用户资料）
  let userList = '';
  for (const user of result.users) {
    const status = user.blocked ? '🚫' : (user.whitelisted ? '⭐' : '•');

    // 尝试获取缓存的用户资料
    const profile = await getUserProfile(user.id);
    let displayInfo = '';

    if (profile) {
      // 使用缓存的资料构建显示信息
      const nameParts = [];
      if (profile.first_name) nameParts.push(profile.first_name);
      if (profile.last_name) nameParts.push(profile.last_name);

      if (nameParts.length > 0) {
        displayInfo = ` (${escapeHtml(nameParts.join(' '))})`;
      }

      // 如果有用户名，也显示
      if (profile.username) {
        displayInfo += ` @${escapeHtml(profile.username)}`;
      }
    } else if (user.name !== 'Unknown') {
      // 回退到已验证列表中的名称
      displayInfo = ` (${escapeHtml(user.name)})`;
    }

    userList += `${status} <code>${user.id}</code>${displayInfo}\n`;
  }

  const filterText = getFilterText(filter);
  const text = `👥 <b>用户管理</b> <code>${filterText}</code>

📊 全部 ${stats.total} | ⭐信任 ${stats.whitelisted} | 🚫拉黑 ${stats.blocked}
第 ${result.page}/${result.totalPages} 页

${userList}`;

  // 构建分页按钮
  const paginationButtons = [];
  if (result.page > 1) {
    paginationButtons.push({ text: '◀️', callback_data: `users_page:${result.page - 1}:${filter}` });
  }
  paginationButtons.push({ text: `${result.page}/${result.totalPages}`, callback_data: 'noop' });
  if (result.page < result.totalPages) {
    paginationButtons.push({ text: '▶️', callback_data: `users_page:${result.page + 1}:${filter}` });
  }

  // 过滤按钮（当前选中的显示为 ✅）
  const filterButtons = [
    { text: (filter === 'all' ? '✅ ' : '') + '全部', callback_data: 'users_filter:all' },
    { text: (filter === 'whitelisted' ? '✅ ' : '') + '信任', callback_data: 'users_filter:whitelisted' },
    { text: (filter === 'blocked' ? '✅ ' : '') + '拉黑', callback_data: 'users_filter:blocked' }
  ];

  const keyboard = {
    inline_keyboard: [
      paginationButtons,
      filterButtons,
      [{ text: '🔄 刷新', callback_data: `refresh_users:${result.page}:${filter}` }],
      [{ text: '◀️ 返回主菜单', callback_data: 'back_to_main' }]
    ]
  };

  return { text, reply_markup: keyboard };
}

// 获取过滤文本
function getFilterText(filter) {
  const map = { all: '', whitelisted: '信任', blocked: '拉黑' };
  return map[filter] || '';
}

// 获取用户统计
async function getUserStats() {
  const keys = await KV.list({ prefix: 'verified-' });
  let total = 0;
  let whitelisted = 0;
  let blocked = 0;

  for (const key of keys.keys) {
    const userId = key.name.replace('verified-', '');
    total++;

    const isWhite = await isWhitelisted(userId);
    if (isWhite) whitelisted++;

    const isBlocked = await KV.get('blocked-' + userId);
    if (isBlocked) blocked++;
  }

  return { total, whitelisted, blocked };
}

// 处理管理员回调
async function handleAdminCallback(callbackQuery) {
  const data = callbackQuery.data;
  const chatId = callbackQuery.message.chat.id;
  const messageId = callbackQuery.message.message_id;
  const adminChatId = String(callbackQuery.from.id); // 使用回调用户的 ID

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
  if (data === 'submenu_verify') {
    const menu = await generateVerifySubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  if (data === 'submenu_spam') {
    const menu = await generateSpamFilterSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  // 关键词管理 - 进入子菜单
  if (data === 'manage_keywords') {
    const menu = await generateKeywordManagementSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  // 关键词管理 - 查看完整列表
  if (data === 'view_all_keywords') {
    const rules = await getSpamFilterRules();
    const allKeywords = [
      '=== 拦截关键词 ===',
      ...(rules.keywords || []),
      '',
      '=== 放行关键词 ===',
      ...(rules.allowKeywords || []),
      '',
      '=== 拦截正则 ===',
      ...(rules.regexes || []),
      '',
      '=== 放行正则 ===',
      ...(rules.allowRegexes || [])
    ].join('\n');

    await requestTelegram('sendMessage', {
      chat_id: chatId,
      text: `<b>完整规则列表:</b>\n<pre>${escapeHtml(allKeywords)}</pre>`,
      parse_mode: 'HTML'
    });

    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  // 关键词管理 - 清空拦截词
  if (data === 'clear_keywords') {
    const rules = await getSpamFilterRules();
    rules.keywords = [];
    rules.regexes = [];
    await setSpamFilterRules(rules);

    const menu = await generateKeywordManagementSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });

    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: '✅ 已清空所有拦截关键词和正则'
    });
  }

  // 关键词管理 - 返回过滤设置
  if (data === 'back_to_spam_filter') {
    const menu = await generateSpamFilterSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  if (data === 'submenu_ai') {
    const menu = await generateAISpamSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

  if (data === 'submenu_spamtopic') {
    const menu = await generateSpamTopicSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id });
  }

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

  if (data.startsWith('forward_mode:')) {
    const mode = data.split(':')[1];
    if (mode === FORWARD_MODES.TOPIC && !hasTopicForwardingPrerequisites()) {
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '⚠️ 请先在环境变量中配置 GROUP_ID 和 ENV_ADMIN_UID',
        show_alert: true
      });
    }

    if (mode === FORWARD_MODES.TOPIC) {
      const readiness = await verifyTopicEnvironment({ force: true, notifyOnFailure: false });
      if (!readiness.ok) {
        return requestTelegram('answerCallbackQuery', {
          callback_query_id: callbackQuery.id,
          text: `Topic mode unavailable: ${describeTopicEnvIssue(readiness)}`,
          show_alert: true
        });
      }
    }

    const applied = await setForwardMode(mode === FORWARD_MODES.TOPIC ? FORWARD_MODES.TOPIC : FORWARD_MODES.DIRECT);
    const menu = await generateForwardModeSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: applied === FORWARD_MODES.TOPIC ? '已切换到话题模式' : '已切换到私聊模式'
    });
  }

  if (data === 'submenu_forward') {
    const menu = await generateForwardModeSubmenu();
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
    const menu = await generateUsersSubmenu(1, 'all');
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
    const parts = data.split(':');
    const page = parseInt(parts[1]) || 1;
    const filter = parts[2] || 'all';
    const menu = await generateUsersSubmenu(page, filter);
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: `第 ${page} 页` });
  }

  // 用户管理 - 过滤切换
  if (data.startsWith('users_filter:')) {
    const filter = data.split(':')[1] || 'all';
    const menu = await generateUsersSubmenu(1, filter);
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    const filterText = { all: '全部', whitelisted: '信任', blocked: '拉黑' }[filter];
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: `已切换: ${filterText}` });
  }

  // 用户管理 - 刷新
  if (data.startsWith('refresh_users:')) {
    const parts = data.split(':');
    const page = parseInt(parts[1]) || 1;
    const filter = parts[2] || 'all';
    const menu = await generateUsersSubmenu(page, filter);
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', { callback_query_id: callbackQuery.id, text: '已刷新' });
  }

  // 垃圾过滤 - 切换状态
  if (data === 'toggle_spam_filter') {
    const isEnabled = await getSpamFilterEnabled();
    await setSpamFilterEnabled(!isEnabled);

    const menu = await generateSpamFilterSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: isEnabled ? '垃圾过滤已关闭' : '垃圾过滤已开启'
    });
  }

  // 垃圾过滤 - 重置规则
  if (data === 'reset_spam_rules') {
    await resetSpamFilterRules();

    const menu = await generateSpamFilterSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: '已重置为默认规则'
    });
  }

  // AI 检测 - 切换状态
  if (data === 'toggle_ai_detection') {
    const aiConfig = await getAISpamDetectionConfig();
    await setAISpamDetectionConfig({
      enabled: !aiConfig.enabled,
      confidenceThreshold: aiConfig.confidenceThreshold || 0.7
    });

    const menu = await generateAISpamSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: !aiConfig.enabled ? 'AI 检测已开启' : 'AI 检测已关闭'
    });
  }

  // 垃圾话题 - 切换状态
  if (data === 'toggle_spam_topic') {
    const config = await getSpamTopicConfig();
    await setSpamTopicConfig({
      ...config,
      enabled: !config.enabled
    });

    const menu = await generateSpamTopicSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: !config.enabled ? '垃圾话题已开启' : '垃圾话题已关闭'
    });
  }

  // 垃圾话题 - 自动创建
  if (data === 'create_spam_topic') {
    const groupId = GROUP_ID;
    if (!groupId) {
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 未配置群组 ID',
        show_alert: true
      });
    }

    // 检查是否已有垃圾话题
    const config = await getSpamTopicConfig();
    if (config.topicId) {
      // 提供强制重新创建的选项
      const text = `⚠️ <b>垃圾话题已存在</b>

当前话题 ID: <code>${config.topicId}</code>

<b>选项:</b>
• 如果话题已被删除，请点击"强制重新创建"
• 如果想使用新话题，请先删除旧话题或手动指定新 ID
• 如果话题正常，请直接使用现有话题`;

      const keyboard = {
        inline_keyboard: [
          [{ text: '🔄 强制重新创建', callback_data: 'force_create_spam_topic' }],
          [{ text: '❌ 取消', callback_data: 'back_to_spamtopic_menu' }]
        ]
      };

      await requestTelegram('editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text: text,
        parse_mode: 'HTML',
        reply_markup: keyboard
      });

      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '垃圾话题已存在'
      });
    }

    const topicId = await createSpamTopic(groupId);
    if (topicId) {
      await setSpamTopicConfig({
        ...config,
        topicId: topicId
      });

      const menu = await generateSpamTopicSubmenu();
      await requestTelegram('editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text: menu.text,
        parse_mode: 'HTML',
        reply_markup: menu.reply_markup
      });
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: `✅ 话题已创建，ID: <code>${topicId}</code>`
      });
    } else {
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 创建话题失败，请检查机器人是否为群组管理员',
        show_alert: true
      });
    }
  }

  // 垃圾话题 - 强制重新创建
  if (data === 'force_create_spam_topic') {
    const groupId = GROUP_ID;
    if (!groupId) {
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 未配置群组 ID',
        show_alert: true
      });
    }

    const config = await getSpamTopicConfig();
    const topicId = await createSpamTopic(groupId);
    if (topicId) {
      // 更新配置
      await setSpamTopicConfig({
        ...config,
        topicId: topicId
      });

      const menu = await generateSpamTopicSubmenu();
      await requestTelegram('editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text: menu.text,
        parse_mode: 'HTML',
        reply_markup: menu.reply_markup
      });
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: `✅ 话题已重新创建，ID: <code>${topicId}</code>`
      });
    } else {
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 创建话题失败，可能话题名称重复或机器人权限不足',
        show_alert: true
      });
    }
  }

  // 返回垃圾话题菜单
  if (data === 'back_to_spamtopic_menu') {
    const menu = await generateSpamTopicSubmenu();
    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: '已返回垃圾话题菜单'
    });
  }

  // 垃圾话题 - 配置话题 ID
  if (data === 'config_spam_topic_id') {
    const config = await getSpamTopicConfig();

    // 提示用户输入话题 ID
    const text = `⚙️ <b>配置垃圾话题 ID</b>

当前话题 ID: <code>${config.topicId || '(未设置)'}</code>

<b>使用方法:</b>
1. 在群组中手动创建一个话题
2. 复制话题 ID（可以通过转发话题中的消息获取）
3. 发送话题 ID 完成配置

<b>或者:</b>
• 发送 "自动创建" 让机器人自动创建话题
• 发送 "取消" 放弃配置`;

    const keyboard = {
      inline_keyboard: [
        [{ text: '◀️ 返回垃圾话题菜单', callback_data: 'back_to_spamtopic_menu' }]
      ]
    };

    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: text,
      parse_mode: 'HTML',
      reply_markup: keyboard
    });

    // 设置一个临时状态，等待用户输入
    await KV.put(`spam_topic_config_wait:${adminChatId}`, 'config');
    // 保存菜单信息
    await KV.put(`spam_topic_menu:${adminChatId}`, JSON.stringify({
      chatId: chatId,
      messageId: messageId
    }), { expirationTtl: 300 });

    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: '请发送话题 ID 或 "自动创建"'
    });
  }

  // 垃圾话题 - 查看垃圾消息
  if (data === 'view_spam_messages') {
    const config = await getSpamTopicConfig();

    if (!config.topicId) {
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 未配置垃圾话题，请先创建或配置话题 ID',
        show_alert: true
      });
    }

    if (!GROUP_ID) {
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 未配置群组 ID',
        show_alert: true
      });
    }

    // 发送跳转到垃圾话题的链接
    const topicLink = `https://t.me/c/${GROUP_ID.replace('-100', '')}/${config.topicId}`;
    const text = `📊 <b>查看垃圾消息</b>

<b>垃圾话题 ID:</b> <code>${config.topicId}</code>
<b>话题链接:</b> <a href="${topicLink}">点击跳转</a>

<b>统计信息:</b>
• 垃圾话题功能：${config.enabled ? '🟢 已开启' : '🔴 已关闭'}
• 管理员通知：${config.notifyAdmin ? '✅' : '❌'}

<b>说明:</b>
• 所有被标记为垃圾的消息会自动转发到垃圾话题
• 您可以在话题中查看和恢复误判的消息
• 恢复消息请回复该消息并发送 /restore

<b>快捷操作:</b>
• 点击话题链接直接跳转到 Telegram 话题
• 返回菜单可重新查看`;

    const keyboard = {
      inline_keyboard: [
        [{ text: '🔗 打开话题', url: topicLink }],
        [{ text: '◀️ 返回垃圾话题菜单', callback_data: 'back_to_spamtopic_menu' }]
      ]
    };

    await requestTelegram('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: text,
      parse_mode: 'HTML',
      reply_markup: keyboard
    });

    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: '已显示垃圾话题信息'
    });
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
    const broadcastMsg = await KV.get(`broadcast_msg:${adminChatId}`);

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
    await KV.delete(`broadcast_msg:${adminChatId}`);
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
  const contextChatId = message.chat?.id ? String(message.chat.id) : null;
  const senderId = message.from ? String(message.from.id) : null;
  const adminChatId = senderId || ADMIN_UID || contextChatId;
  const replyChatId = reply ? (reply.chat?.id ? String(reply.chat.id) : (contextChatId || adminChatId)) : null;

  // 【话题模式支持】检测是否在话题中发送消息
  const isTopicMode = await isTopicForwardingEnabled();
  const isInTopic = isTopicMode && contextChatId === GROUP_ID && message.message_thread_id;

  // 辅助函数：获取回复目标（话题模式或私聊模式）
  const getReplyTarget = () => {
    if (isInTopic) {
      return {
        chat_id: contextChatId,
        message_thread_id: message.message_thread_id
      };
    }
    return {
      chat_id: adminChatId
    };
  };

  // 【垃圾话题配置】检查是否在配置垃圾话题 ID 的等待状态
  const spamTopicWaitKey = `spam_topic_config_wait:${adminChatId}`;
  const isWaitingForSpamTopicId = await KV.get(spamTopicWaitKey);
  if (isWaitingForSpamTopicId) {
    await KV.delete(spamTopicWaitKey);

    // 获取最后一个菜单消息 ID（从 KV 中存储）
    const lastMenuKey = `spam_topic_menu:${adminChatId}`;
    const lastMenuInfo = await KV.get(lastMenuKey);
    let lastMenuId = null;
    let lastChatId = adminChatId;
    if (lastMenuInfo) {
      try {
        const info = JSON.parse(lastMenuInfo);
        lastMenuId = info.messageId;
        lastChatId = info.chatId;
      } catch (e) {
        // 忽略解析错误
      }
    }

    if (text.toLowerCase() === '取消') {
      if (lastMenuId) {
        const menu = await generateSpamTopicSubmenu();
        await requestTelegram('editMessageText', {
          chat_id: lastChatId,
          message_id: lastMenuId,
          text: menu.text,
          parse_mode: 'HTML',
          reply_markup: menu.reply_markup
        });
      }
      return sendMessage({
        chat_id: adminChatId,
        text: '❌ 已取消配置垃圾话题 ID'
      });
    }

    if (text.toLowerCase() === '自动创建') {
      const topicId = await createSpamTopic(GROUP_ID);
      if (topicId) {
        const config = await getSpamTopicConfig();
        await setSpamTopicConfig({
          ...config,
          topicId: topicId
        });

        if (lastMenuId) {
          const menu = await generateSpamTopicSubmenu();
          await requestTelegram('editMessageText', {
            chat_id: lastChatId,
            message_id: lastMenuId,
            text: menu.text,
            parse_mode: 'HTML',
            reply_markup: menu.reply_markup
          });
        }

        return sendMessage({
          chat_id: adminChatId,
          text: `✅ 垃圾话题已自动创建，ID: <code>${topicId}</code>\n\n请在菜单中开启垃圾话题功能`
        });
      } else {
        return sendMessage({
          chat_id: adminChatId,
          text: '❌ 自动创建失败，请检查机器人是否为群组管理员'
        });
      }
    }

    // 尝试解析话题 ID（支持纯数字或带链接格式）
    let topicId = text.trim();
    const urlMatch = text.match(/\/c\/(\d+)\/(\d+)/);
    if (urlMatch) {
      topicId = urlMatch[2];
    }

    if (!/^\d+$/.test(topicId)) {
      return sendMessage({
        chat_id: adminChatId,
        text: '❌ 无效的话题 ID，请输入纯数字或话题链接'
      });
    }

    const config = await getSpamTopicConfig();
    await setSpamTopicConfig({
      ...config,
      topicId: topicId
    });

    // 刷新菜单
    if (lastMenuId) {
      const menu = await generateSpamTopicSubmenu();
      await requestTelegram('editMessageText', {
        chat_id: lastChatId,
        message_id: lastMenuId,
        text: menu.text,
        parse_mode: 'HTML',
        reply_markup: menu.reply_markup
      });
    }

    return sendMessage({
      chat_id: adminChatId,
      text: `✅ 垃圾话题 ID 已设置：<code>${topicId}</code>\n\n请在菜单中开启垃圾话题功能`
    });
  }

  // 【修复】检查是否以 / 开头但不是有效命令
  // 如果是无效命令且是回复消息，防止转发给用户
  const validCommands = ['/help', '/menu', '/welcome', '/autoreply', '/ban', '/unban', '/reset', '/trust', '/untrust', '/broadcast', '/bcancel'];
  const isValidCommand = validCommands.some(cmd => text === cmd || text.startsWith(cmd + ' '));
  const isCommandLike = text.startsWith('/') && text.length > 1;

  // 【话题模式】如果在话题中发送命令，只在话题内回复，不转发
  if (isInTopic && isCommandLike) {
    Logger.info('admin_command_in_topic', { text, threadId: message.message_thread_id });
  }

  // --- 管理指令区域 ---

  // 指令：/help - 显示帮助信息
  if (text === '/help') {
    const verifyMode = await getVerifyMode();
    const spamFilterEnabled = await getSpamFilterEnabled();
    const replyTarget = getReplyTarget();
    return sendMessage({
      ...replyTarget,
      text: '🤖 <b>SafeRelay 管理面板</b>\n\n' +
        '<b>常用指令：</b>\n' +
        '/menu - 打开图形菜单\n' +
        '/help - 显示帮助\n' +
        '/broadcast - 广播消息\n' +
        '/bcancel - 取消广播\n' +
        '/cleanup - 清理失效话题\n' +
        '/cachestats - 查看缓存统计\n' +
        '/clearcache - 清空所有缓存\n\n' +
        '<b>用户管理（回复消息或指定ID）：</b>\n' +
        '/ban - 封禁用户\n' +
        '/unban - 解封用户\n' +
        '/reset - 重置验证\n' +
        '/trust - 信任用户(白名单)\n' +
        '/untrust - 取消信任\n\n' +
        '<b>消息设置：</b>\n' +
        '/welcome - 欢迎消息\n' +
        '/autoreply - 自动回复\n\n' +
        '<b>转发 / 系统：</b>\n' +
        '/cleanup - 清理失效话题\n' +
        '/cachestats - 查看缓存统计\n' +
        '/clearcache - 清空缓存\n' +
        '在 /menu → 转发模式 中切换私聊/话题\n\n' +
        '<b>快捷操作：</b> 回复用户消息即可转发\n\n' +
        '<i>验证: ' + getVerifyModeName(verifyMode) + ' | 过滤: ' + (spamFilterEnabled ? '开' : '关') + '</i>',
      parse_mode: 'HTML'
    });
  }



  // 指令：/menu - 显示管理菜单
  if (text === '/menu') {
    const menu = await generateMainMenu();
    const replyTarget = getReplyTarget();
    return sendMessage({
      ...replyTarget,
      text: menu.text,
      parse_mode: 'HTML',
      reply_markup: menu.reply_markup
    });
  }

  // 指令：/welcome - 设置欢迎消息
  if (text.startsWith('/welcome')) {
    const content = text.slice(8).trim();
    const replyTarget = getReplyTarget();
    if (!content || content === 'delete') {
      await setConfig(CONFIG_KEYS.WELCOME_MSG, '');
      return sendMessage({
        ...replyTarget,
        text: '✅ 欢迎消息已删除（恢复默认）。'
      });
    }
    await setConfig(CONFIG_KEYS.WELCOME_MSG, content);
    return sendMessage({
      ...replyTarget,
      text: '✅ 欢迎消息已设置。'
    });
  }

  // 指令：/autoreply - 设置自动回复
  if (text.startsWith('/autoreply')) {
    const content = text.slice(10).trim();
    const replyTarget = getReplyTarget();
    if (!content || content === 'off') {
      await setConfig(CONFIG_KEYS.AUTO_REPLY_MSG, '');
      return sendMessage({
        ...replyTarget,
        text: '✅ 自动回复已关闭。'
      });
    }
    await setConfig(CONFIG_KEYS.AUTO_REPLY_MSG, content);
    return sendMessage({
      ...replyTarget,
      text: '✅ 自动回复已设置。'
    });
  }

  // 关键词管理 - 添加放行词
  if (text.startsWith('allow:')) {
    const keyword = text.slice(6).trim();
    const replyTarget = getReplyTarget();
    if (keyword) {
      const rules = await getSpamFilterRules();
      if (!rules.allowKeywords) rules.allowKeywords = [];
      if (!rules.allowKeywords.includes(keyword)) {
        rules.allowKeywords.push(keyword);
        await setSpamFilterRules(rules);
        return sendMessage({ ...replyTarget, text: `✅ 已添加放行关键词：<code>${escapeHtml(keyword)}</code>`, parse_mode: 'HTML' });
      }
      return sendMessage({ ...replyTarget, text: '⚠️ 该放行关键词已存在。' });
    }
  }

  // 关键词管理 - 添加正则
  if (text.startsWith('regex:')) {
    const regex = text.slice(6).trim();
    if (regex) {
      const rules = await getSpamFilterRules();
      if (!rules.regexes) rules.regexes = [];
      try {
        new RegExp(regex, 'i'); // 验证正则有效性
        rules.regexes.push(regex);
        await setSpamFilterRules(rules);
        return sendMessage({ chat_id: adminChatId, text: `✅ 已添加正则规则：<code>${escapeHtml(regex)}</code>`, parse_mode: 'HTML' });
      } catch (e) {
        return sendMessage({ chat_id: adminChatId, text: '❌ 正则表达式无效。' });
      }
    }
  }

  // 关键词管理 - 删除拦截词
  if (text.startsWith('del:')) {
    const keyword = text.slice(4).trim();
    if (keyword) {
      const rules = await getSpamFilterRules();
      const index = (rules.keywords || []).indexOf(keyword);
      if (index > -1) {
        rules.keywords.splice(index, 1);
        await setSpamFilterRules(rules);
        return sendMessage({ chat_id: adminChatId, text: `✅ 已删除拦截关键词：<code>${escapeHtml(keyword)}</code>`, parse_mode: 'HTML' });
      }
      return sendMessage({ chat_id: adminChatId, text: '⚠️ 未找到该拦截关键词。' });
    }
  }

  // 关键词管理 - 删除放行词
  if (text.startsWith('delallow:')) {
    const keyword = text.slice(9).trim();
    if (keyword) {
      const rules = await getSpamFilterRules();
      const index = (rules.allowKeywords || []).indexOf(keyword);
      if (index > -1) {
        rules.allowKeywords.splice(index, 1);
        await setSpamFilterRules(rules);
        return sendMessage({ chat_id: adminChatId, text: `✅ 已删除放行关键词：<code>${escapeHtml(keyword)}</code>`, parse_mode: 'HTML' });
      }
      return sendMessage({ chat_id: adminChatId, text: '⚠️ 未找到该放行关键词。' });
    }
  }

  // 关键词管理 - 清空默认规则
  if (text === '清空默认') {
    await resetSpamFilterRules();
    return sendMessage({ chat_id: adminChatId, text: '✅ 已重置为默认规则。' });
  }

  // 链接数量设置
  if (text.startsWith('max_links:')) {
    const num = parseInt(text.slice(10));
    if (!isNaN(num) && num >= 0) {
      const rules = await getSpamFilterRules();
      rules.maxLinks = num;
      await setSpamFilterRules(rules);
      return sendMessage({ chat_id: adminChatId, text: `✅ 链接限制已设置为：${num}` });
    }
    return sendMessage({ chat_id: adminChatId, text: '⚠️ 请输入有效的数字。' });
  }

  // 普通文本 - 添加为拦截关键词（如果不是命令）
  if (!reply && text && !text.startsWith('/') && text.length > 0) {
    // 检查是否在关键词管理上下文中
    const rules = await getSpamFilterRules();
    if (!rules.keywords) rules.keywords = [];

    // 避免重复添加
    if (!rules.keywords.includes(text)) {
      rules.keywords.push(text);
      await setSpamFilterRules(rules);
      return sendMessage({ chat_id: adminChatId, text: `✅ 已添加拦截关键词：<code>${escapeHtml(text)}</code>\n发送 del:${escapeHtml(text)} 删除`, parse_mode: 'HTML' });
    }
  }

  // 指令：/ban [ID] (支持回复或手输)
  if (text === '/ban' || text.startsWith('/ban ')) {
    const targetId = await getTargetId(message, '/ban');
    const replyTarget = getReplyTarget();
    if (targetId) {
      await KV.put('blocked-' + targetId, 'true'); // 永久拉黑
      memDelete('blocked-' + targetId); // 清除缓存
      await removeVerifiedUser(targetId); // 从已验证列表移除
      return sendMessage({ ...replyTarget, text: `🚫 用户 <code>${targetId}</code> 已被封禁。` });
    } else {
      return sendMessage({ ...replyTarget, text: '⚠️ 格式错误。\n请回复用户消息发送 /ban\n或发送 /ban 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/unban [ID] (支持回复或手输)
  if (text === '/unban' || text.startsWith('/unban ')) {
    const targetId = await getTargetId(message, '/unban');
    const replyTarget = getReplyTarget();
    if (targetId) {
      await KV.delete('blocked-' + targetId);
      memDelete('blocked-' + targetId); // 清除缓存
      return sendMessage({ ...replyTarget, text: `✅ 用户 <code>${targetId}</code> 已解封。` });
    } else {
      return sendMessage({ ...replyTarget, text: '⚠️ 格式错误。\n请回复用户消息发送 /unban\n或发送 /unban 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/reset [ID] (支持回复或手输)
  if (text === '/reset' || text.startsWith('/reset ')) {
    const targetId = await getTargetId(message, '/reset');
    const replyTarget = getReplyTarget();
    if (targetId) {
      // 检查用户是否在白名单中
      const isWhite = await isWhitelisted(targetId);
      if (isWhite) {
        return sendMessage({
          ...replyTarget,
          text: `⚠️ 用户 <code>${targetId}</code> 在白名单中，无需验证即可发送消息。\n\n如需限制该用户，请先使用 /delwhite <code>${targetId}</code> 删除白名单。`
        });
      }

      await KV.delete('verified-' + targetId);
      memDelete('verified-' + targetId); // 清除缓存
      await removeVerifiedUser(targetId); // 从已验证列表移除
      return sendMessage({ ...replyTarget, text: `🔄 用户 <code>${targetId}</code> 验证状态已取消。` });
    } else {
      return sendMessage({ ...replyTarget, text: '⚠️ 格式错误。\n请回复用户消息发送 /reset\n或发送 /reset 123456 (必须是数字 ID)' });
    }
  }

  // 指令：/broadcast - 广播消息
  if (text === '/broadcast' || text.startsWith('/broadcast ')) {
    const broadcastMsg = text === '/broadcast' ? '' : text.slice(10).trim();
    if (!broadcastMsg) {
      return sendMessage({
        chat_id: adminChatId,
        text: '⚠️ 格式错误。\n用法：/broadcast 消息内容\n\n支持 HTML 格式：\n<b>粗体</b> <i>斜体</i> <code>代码</code>'
      });
    }

    // 检查 24 小时冷却（使用增强的限流）
    const rateLimit = checkRateLimit(adminChatId, 'broadcast');
    if (!rateLimit.allowed) {
      const remainingHours = Math.ceil(rateLimit.retryAfter / 3600);
      return sendMessage({
        chat_id: adminChatId,
        text: `⏳ 广播冷却中，请 ${remainingHours} 小时后再试。\n\n限额：${rateLimit.limit} 次/24 小时`
      });
    }

    // 记录限流
    const lastBroadcast = await KV.get(`broadcast_cooldown:${adminChatId}`);
    if (lastBroadcast) {
      const lastTime = parseInt(lastBroadcast);
      const now = Date.now();
      const cooldownMs = 24 * 60 * 60 * 1000; // 24 小时
      const remainingMs = cooldownMs - (now - lastTime);

      if (remainingMs > 0) {
        const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));
        return sendMessage({
          chat_id: adminChatId,
          text: `⏳ 广播冷却中，请 ${remainingHours} 小时后再试。`
        });
      }
    }

    // 保存消息到 KV（24小时过期）
    await KV.put(`broadcast_msg:${adminChatId}`, broadcastMsg, { expirationTtl: 86400 });
    // 记录广播时间
    await KV.put(`broadcast_cooldown:${adminChatId}`, Date.now().toString(), { expirationTtl: 86400 });

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
      chat_id: adminChatId,
      text: `${statusIcon} <b>广播${statusText}</b>\n\n✅ 已发送：${result.sent}/${result.total}\n❌ 失败：${result.failed}${result.skipped > 0 ? `\n⏭️ 跳过（封禁）：${result.skipped}` : ''}`,
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: inlineKeyboard }
    });
  }

  // 指令：/trust [ID] - 添加白名单（信任用户）
  if (text === '/trust' || text.startsWith('/trust ')) {
    const targetId = await getTargetId(message, '/trust');
    const replyTarget = getReplyTarget();
    if (targetId) {
      await addToWhitelist(targetId);
      return sendMessage({ ...replyTarget, text: `✅ 已信任用户 <code>${targetId}</code>` });
    } else {
      // 如果没有指定 ID，显示当前白名单状态
      return sendMessage({ ...replyTarget, text: '📋 请回复用户消息或发送 /trust 123456 来信任用户' });
    }
  }

  // 指令：/untrust [ID] - 删除白名单（取消信任）
  if (text === '/untrust' || text.startsWith('/untrust ')) {
    const targetId = await getTargetId(message, '/untrust');
    const replyTarget = getReplyTarget();
    if (targetId) {
      await removeFromWhitelist(targetId);
      return sendMessage({ ...replyTarget, text: `✅ 已取消信任用户 <code>${targetId}</code>` });
    } else {
      return sendMessage({ ...replyTarget, text: '📋 请回复用户消息或发送 /untrust 123456 来取消信任' });
    }
  }

  // 指令：/bcancel - 取消广播（保留命令方式作为备选）
  if (text === '/bcancel') {
    await KV.delete(`broadcast_msg:${adminChatId}`);
    return sendMessage({
      chat_id: adminChatId,
      text: '✅ 已取消广播'
    });
  }

  // 指令：/cleanup - 批量清理失效的话题映射
  if (text === '/cleanup' || text.startsWith('/cleanup ')) {
    const args = text.split(/\s+/);
    const dryRun = args.includes('--dry-run') || args.includes('-n');
    const cleanAll = args.includes('--all') || args.includes('-a');

    return handleCleanupCommand(message, { dryRun, cleanAll }, adminChatId);
  }

  // 指令：/cachestats - 查看缓存统计
  if (text === '/cachestats') {
    const stats = getCacheStats();
    const text = `📊 <b>缓存统计信息</b>\n\n` +
      `<b>L1 内存缓存：</b>\n` +
      `  命中：${stats.l1.hits}\n` +
      `  未命中：${stats.l1.misses}\n` +
      `  命中率：${stats.l1.hitRate}\n` +
      `  缓存大小：${stats.l1.size} 条目\n\n` +
      `<b>L2 KV 缓存：</b>\n` +
      `  命中：${stats.l2.hits}\n` +
      `  未命中：${stats.l2.misses}\n` +
      `  命中率：${stats.l2.hitRate}\n\n` +
      `<i>提示：命中率越高，性能越好</i>`;

    return sendMessage({
      chat_id: adminChatId,
      text: text,
      parse_mode: 'HTML'
    });
  }

  // 指令：/clearcache - 清空所有缓存
  if (text === '/clearcache') {
    clearAllCache();
    return sendMessage({
      chat_id: adminChatId,
      text: '✅ 已清空所有缓存\n\nL1 内存缓存和统计信息已重置。\nL2 KV 缓存将在到期后自动清理。',
      parse_mode: 'HTML'
    });
  }

  // --- 普通回复逻辑 ---

  // 【话题模式】在话题中发送命令时，不转发到私聊
  if (isInTopic && isCommandLike) {
    // 如果是有效命令，已经在上面处理了
    // 如果是无效命令，提示用户
    if (!isValidCommand) {
      return sendMessage({
        chat_id: contextChatId,
        text: `⚠️ 无效命令 "${text.split(' ')[0]}"\n\n请发送 /help 查看所有可用指令。`,
        parse_mode: 'HTML',
        message_thread_id: message.message_thread_id
      });
    }
    // 有效命令已处理，这里不会执行到
    return;
  }

  // 检查是否在回复转发消息或编辑提示消息
  if (reply) {
    let guestChatId = null;

    // 【话题模式支持】从话题 ID 查找用户
    const isTopicMode = await isTopicForwardingEnabled();
    if (isTopicMode && reply.message_thread_id && contextChatId === GROUP_ID) {
      const threadId = reply.message_thread_id;
      guestChatId = await KV.get(`thread:${threadId}`);
      Logger.info('admin_reply_in_topic_mode', { adminChatId, threadId, guestChatId });
    }

    // 情况 1：回复转发消息
    if (!guestChatId && (reply.forward_from || reply.forward_sender_name)) {
      guestChatId = await KV.get('msg-map-' + reply.message_id);
    }
    // 情况 2：回复编辑提示消息（以 ✏️ 开头）
    if (!guestChatId && reply.text && reply.text.startsWith('✏️')) {
      guestChatId = await KV.get('msg-map-' + reply.message_id);
    }
    // 情况 3：回复垃圾过滤菜单消息
    if (!guestChatId && reply.text && reply.text.includes('🗑 <b>垃圾消息过滤设置</b>')) {
      // 解析编辑内容
      const newRules = parseSpamRulesEdit(text);
      await setSpamFilterRules(newRules);

      // 刷新菜单
      const menu = await generateSpamFilterSubmenu();
      await requestTelegram('editMessageText', {
        chat_id: replyChatId || contextChatId || adminChatId,
        message_id: reply.message_id,
        text: menu.text,
        parse_mode: 'HTML',
        reply_markup: menu.reply_markup
      });

      return sendMessage({
        chat_id: adminChatId,
        text: '✅ 垃圾过滤规则已更新'
      });
    }

    if (!guestChatId) {
      guestChatId = await KV.get('msg-map-' + reply.message_id);
    }

    // 【修复】检查是否是回复消息但发送了无效命令
    if (isCommandLike && !isValidCommand) {
      return sendMessage({
        chat_id: adminChatId,
        text: `⚠️ 无效命令 "${text.split(' ')[0]}"\n\n请检查命令拼写，或发送 /help 查看所有可用指令。`,
        parse_mode: 'HTML'
      });
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
        chat_id: adminChatId,
        text: '⚠️ 未找到原用户映射，可能消息太旧或被清理了缓存。'
      });
    }
  } else {
    // 既不是指令也不是回复，提示使用 /help
    return sendMessage({
      chat_id: adminChatId,
      text: '🤖 请发送 /help 查看所有可用指令，或直接回复用户消息进行转发。',
      parse_mode: 'HTML'
    });
  }
}

// 批量清理失效的话题映射
async function handleCleanupCommand(message, options = {}, overrideChatId = null) {
  const { dryRun = false, cleanAll = false } = options;
  const adminChatId = overrideChatId || (message.chat?.id ? String(message.chat.id) : ADMIN_UID);
  const groupId = getEnv('GROUP_ID');

  if (!groupId) {
    return sendMessage({
      chat_id: adminChatId,
      text: '⚠️ 未配置 GROUP_ID 环境变量\n\n话题清理功能仅在使用论坛群组时需要。\n请在 Cloudflare 环境变量中设置 GROUP_ID。'
    });
  }

  // 发送开始通知
  const startMsg = dryRun ? '🔍 <b>开始扫描失效话题（预览模式）</b>' : '🧹 <b>开始清理失效话题</b>';
  const progressMsg = await sendMessage({
    chat_id: adminChatId,
    text: `${startMsg}\n\n正在扫描用户数据...`,
    parse_mode: 'HTML'
  });

  try {
    // 获取所有用户数据
    const userKeys = [];
    let cursor = undefined;

    // 分批读取所有 user:* 键
    while (true) {
      const listOptions = {
        prefix: 'user:',
        limit: 1000
      };
      if (cursor) {
        listOptions.cursor = cursor;
      }

      const result = await KV.list(listOptions);
      for (const key of result.keys) {
        userKeys.push(key.name);
      }

      if (result.list_complete) {
        break;
      }
      cursor = result.cursor;
    }

    Logger.info('cleanup_scan_started', { totalKeys: userKeys.length });

    let invalidCount = 0;
    let cleanedCount = 0;
    let errorCount = 0;
    const invalidUsers = [];

    // 检查每个用户的话题
    for (let i = 0; i < userKeys.length; i++) {
      const key = userKeys[i];
      const userId = key.replace('user:', '');

      try {
        const userData = await safeGetJSON(key, null);
        if (!userData || !userData.thread_id) {
          continue; // 没有话题 ID，跳过
        }

        const threadId = userData.thread_id;

        // 检查话题是否有效
        const isValid = await validateForumThread(groupId, threadId);

        if (!isValid) {
          invalidCount++;
          invalidUsers.push({ userId, threadId });

          if (!dryRun) {
            // 删除失效的映射
            await safeKvDelete(key); // user:{userId}
            await safeKvDelete(`thread:${threadId}`); // thread:{threadId}
            await safeKvDelete(`verified-${userId}`); // verified-{userId}

            // 清理缓存
            memDelete(key);
            memDelete(`thread:${threadId}`);
            memDelete(`verified-${userId}`);
            threadHealthCache.delete(`thread:${threadId}`);

            cleanedCount++;
          }
        }

        // 每 100 个用户更新一次进度
        if ((i + 1) % 100 === 0) {
          await requestTelegram('editMessageText', {
            chat_id: adminChatId,
            message_id: progressMsg.result.message_id,
            text: `${startMsg}\n\n进度：${i + 1}/${userKeys.length}\n已发现失效：${invalidCount}${!dryRun ? `\n已清理：${cleanedCount}` : ''}`,
            parse_mode: 'HTML'
          });
        }

        // 避免触发速率限制
        if ((i + 1) % 50 === 0) {
          await new Promise(r => setTimeout(r, 100));
        }

      } catch (e) {
        errorCount++;
        Logger.error('cleanup_check_user_failed', e, { userId, key });
      }
    }

    // 更新最终结果
    const resultText = [
      `✅ <b>清理完成</b>`,
      ``,
      `📊 <b>统计信息：</b>`,
      `• 总用户数：${userKeys.length}`,
      `• 失效话题：${invalidCount}`,
      !dryRun ? `• 已清理：${cleanedCount}` : `• 预览模式：未执行清理`,
      errorCount > 0 ? `• 错误：${errorCount}` : null
    ].filter(Boolean).join('\n');

    if (invalidCount > 0 && !dryRun) {
      // 附加详细信息（最多显示 20 个）
      const detailLimit = Math.min(20, invalidUsers.length);
      const details = invalidUsers.slice(0, detailLimit)
        .map(u => `• User ${u.userId}: Topic ${u.threadId}`)
        .join('\n');

      const moreText = invalidUsers.length > detailLimit ? `\n... 还有 ${invalidUsers.length - detailLimit} 个` : '';

      await requestTelegram('editMessageText', {
        chat_id: adminChatId,
        message_id: progressMsg.result.message_id,
        text: `${resultText}\n\n<b>失效用户列表：</b>\n${details}${moreText}`,
        parse_mode: 'HTML'
      });
    } else {
      await requestTelegram('editMessageText', {
        chat_id: adminChatId,
        message_id: progressMsg.result.message_id,
        text: resultText,
        parse_mode: 'HTML'
      });
    }

    Logger.info('cleanup_completed', {
      total: userKeys.length,
      invalid: invalidCount,
      cleaned: cleanedCount,
      errors: errorCount,
      dryRun
    });

  } catch (e) {
    Logger.error('cleanup_failed', e);
    await requestTelegram('editMessageText', {
      chat_id: adminChatId,
      message_id: progressMsg.result.message_id,
      text: `❌ <b>清理失败</b>\n\n错误信息：${e.message}\n\n请检查日志或重试。`,
      parse_mode: 'HTML'
    });
  }
}

// 处理验证流程
async function handleVerification(message, chatId, origin) {
  // 获取当前验证模式
  const verifyMode = await getVerifyMode();

  // 【并发保护】暂存当前消息（如果有）
  if (message && message.message_id) {
    const queue = await appendPendingQueue(chatId, message.message_id);
    Logger.debug('message_queued_for_verification', { userId: chatId, messageId: message.message_id, queueLength: queue.length });

    // 如果队列已满，提示用户
    if (queue.length >= CONFIG.PENDING_MAX_MESSAGES) {
      await sendMessage({
        chat_id: chatId,
        text: `📝 消息已暂存，完成验证后会自动发送（最多暂存${CONFIG.PENDING_MAX_MESSAGES}条）`
      });
    }
  }

  // 本地题库验证
  if (verifyMode === 'local_quiz') {
    // 【并发保护】检查是否已有进行中的验证
    const existingChallenge = await getQuizChallenge(chatId);
    if (existingChallenge) {
      // 已有验证在进行中，不重复下发题目
      Logger.debug('verification_already_in_progress', { userId: chatId });
      return;
    }

    // 检查频率限制
    const limitCheck = await checkLocalQuizTriggerLimit(chatId);
    if (!limitCheck.allowed) {
      return sendMessage({
        chat_id: chatId,
        text: '⏳ 验证尝试过于频繁，请5分钟后再试。'
      });
    }

    // 创建新题目
    const { question } = await createQuizChallenge(chatId);

    // 获取自定义欢迎消息
    const welcomeMsg = await getConfig(CONFIG_KEYS.WELCOME_MSG);
    const verificationText = welcomeMsg
      ? welcomeMsg + '\n\n🛡 请回答以下问题以继续对话：'
      : '🛡 为了防止垃圾消息，请回答以下问题：';

    return sendMessage({
      chat_id: chatId,
      text: `${verificationText}\n\n<b>${question.q}</b>`,
      parse_mode: 'HTML',
      reply_markup: generateQuizKeyboard(question)
    });
  }

  // Turnstile 验证或双重验证
  let session;
  try {
    session = await createTurnstileSession(chatId);
  } catch (e) {
    Logger.error('turnstile_session_create_failed', e, { userId: chatId });
  }

  if (!session) {
    return sendMessage({
      chat_id: chatId,
      text: '⚠️ 系统暂时无法创建验证会话，请稍后再试。'
    });
  }

  const verifyUrl = `${origin}/verify?session=${encodeURIComponent(session.sessionId)}&sig=${encodeURIComponent(session.signature)}`;

  // 获取自定义欢迎消息
  const welcomeMsg = await getConfig(CONFIG_KEYS.WELCOME_MSG);
  let verificationText;

  if (verifyMode === 'both') {
    verificationText = welcomeMsg
      ? welcomeMsg + '\n\n🛡 请完成以下两步验证以继续对话：'
      : '🛡 为了防止垃圾消息，请完成以下两步验证：';
  } else {
    verificationText = welcomeMsg
      ? welcomeMsg + '\n\n🛡 请完成下方验证以继续对话：'
      : '🛡 为了防止垃圾消息，请点击下方按钮完成人机验证：';
  }

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
  const siteKey = getTurnstileSiteKey();
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  const sessionSignature = url.searchParams.get('sig');

  if (!siteKey) {
    return new Response('Turnstile 未配置', {
      status: 503,
      headers: { 'content-type': 'text/plain;charset=UTF-8' }
    });
  }

  if (!sessionId || !sessionSignature) {
    return new Response('Invalid verification session', {
      status: 400,
      headers: { 'content-type': 'text/plain;charset=UTF-8' }
    });
  }

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
                  <div id="turnstile-widget" class="cf-turnstile" data-sitekey="${siteKey}" data-callback="onVerify" data-theme="auto"></div>
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
              const session = urlParams.get('session');
              const signature = urlParams.get('sig');
              
              if (!session || !signature) {
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
                  body: JSON.stringify({ token, session, signature, userInfo })
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
    const { token, session, signature, userInfo } = await request.json();

    if (!token || !session || !signature) {
      return new Response('Missing token or session', { status: 400 });
    }

    const sessionInfo = await validateTurnstileSession(session, signature);
    if (!sessionInfo.valid) {
      return new Response('Invalid verification session', { status: 400 });
    }

    const uid = sessionInfo.userId;
    const secretKey = getTurnstileSecretKey();
    if (!secretKey) {
      return new Response('Turnstile not configured', { status: 503 });
    }

    const formData = new FormData();
    formData.append('secret', secretKey);
    formData.append('response', token);

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData
    }).then(r => r.json());

    if (!result.success) {
      Logger.warn('turnstile_verification_failed', { userId: uid, errors: result['error-codes'] });
      return new Response('Verification failed', { status: 400 });
    }

    const allowedHostnames = getTurnstileAllowedHostnames();
    if (allowedHostnames.length && (!result.hostname || !allowedHostnames.includes(result.hostname))) {
      Logger.warn('turnstile_hostname_mismatch', { userId: uid, hostname: result.hostname });
      return new Response('Hostname mismatch', { status: 400 });
    }

    const expectedAction = getTurnstileExpectedAction();
    if (expectedAction && result.action && result.action !== expectedAction) {
      Logger.warn('turnstile_action_mismatch', { userId: uid, action: result.action, expected: expectedAction });
      return new Response('Action mismatch', { status: 400 });
    }

    await consumeTurnstileSession(session);

    const verifiedKey = 'verified-' + String(uid);
    await KV.put(verifiedKey, 'true', { expirationTtl: VERIFICATION_TTL });
    memSet(verifiedKey, 'true', 5 * 60 * 1000);

    let displayName = 'Unknown';
    if (userInfo) {
      if (userInfo.first_name || userInfo.last_name) {
        displayName = `${userInfo.first_name || ''} ${userInfo.last_name || ''}`.trim();
      } else if (userInfo.username) {
        displayName = `@${userInfo.username}`;
      }
    }

    await addVerifiedUser(uid, displayName);

    if (userInfo) {
      await upsertUserProfileFromUpdate(userInfo);
    }

    const pendingResult = await processPendingMessagesAfterVerification(uid);
    Logger.info('turnstile_verification_success', { userId: uid, pendingForwarded: pendingResult.forwarded });

    let successMsg = `✅ 验证通过！

如果重复验证请等待一分钟后再发送消息，以确保验证状态同步。`;
    if (pendingResult.forwarded > 0) {
      successMsg = `✅ 验证通过！

📩 刚才的 ${pendingResult.forwarded} 条消息已送达管理员。`;
    }
    await sendMessage({
      chat_id: uid,
      text: successMsg
    });

    let usernameLine = '';
    if (userInfo && userInfo.username) {
      usernameLine = `
📎 @${escapeHtml(userInfo.username)}`;
    }
    await requestTelegram('sendMessage', {
      chat_id: ADMIN_UID,
      text: `✅ <b>新用户验证通过</b>

🆔 <code>${uid}</code> (${escapeHtml(displayName)})${usernameLine}`,
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: {
        inline_keyboard: [[
          { text: '👤 打开用户资料', url: `tg://user?id=${uid}` }
        ]]
      }
    });

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
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
  // 【修复】过滤 /start 命令，不转发给管理员
  const text = (message.text || '').trim();
  if (text === '/start') {
    return; // 静默忽略 /start 命令
  }

  const userId = message.chat.id.toString();
  Logger.info('handle_guest_message_start', { userId, text: text ? text.substring(0, 50) : '[media]' });

  // 记录统计信息
  await incrementMessageCount();
  await recordActiveUser(userId);

  const desiredTopicMode = await isTopicForwardingEnabled();
  Logger.info('handle_guest_message_mode_check', { userId, desiredTopicMode, GROUP_ID, ADMIN_UID });

  let topicContext = null;
  if (desiredTopicMode) {
    Logger.info('handle_guest_message_calling_ensure_topic', { userId });
    topicContext = await ensureUserTopic(userId, message.from || await getUserProfile(userId));
    Logger.info('handle_guest_message_topic_context', { userId, topicContext });
    if (!topicContext) {
      Logger.warn('topic_forwarding_unavailable', { userId });
    }
  }

  Logger.info('handle_guest_message_before_media_group', { userId, hasTopicContext: !!topicContext });
  return handleMediaGroup(message, async (messages) => {
    Logger.info('handle_guest_message_in_media_group', { userId, messageCount: messages.length });
    if (topicContext && topicContext.threadId) {
      const topicResult = await forwardMessagesToTopic(messages, userId, topicContext.threadId);
      Logger.info('handle_guest_message_topic_forward_result', { userId, ok: topicResult?.ok });
      if (topicResult?.ok) {
        return topicResult;
      }
    }
    Logger.info('handle_guest_message_forwarding_to_admin', { userId });
    return forwardMessagesToAdmin(messages, userId);
  });
}

async function forwardMessagesToAdmin(messages, userId) {
  if (!ADMIN_UID) {
    Logger.error('admin_uid_missing_forward', { userId });
    return { ok: false, errorType: 'admin_missing' };
  }
  return forwardMessagesToTarget(messages, userId, { chatId: ADMIN_UID, label: 'admin_dm' });
}

async function forwardMessagesToTopic(messages, userId, threadId, attempt = 1) {
  if (!GROUP_ID) return { ok: false, errorType: 'group_missing' };
  const target = { chatId: GROUP_ID, threadId, label: 'topic' };
  const result = await forwardMessagesToTarget(messages, userId, target);
  if (result.ok) {
    return result;
  }

  if (result.errorType === 'thread_not_found' && attempt < 2) {
    await invalidateUserTopicMapping(userId, threadId);
    const profile = await getUserProfile(userId);
    const newTopic = await ensureUserTopic(userId, profile);
    if (newTopic?.threadId && newTopic.threadId !== threadId) {
      return forwardMessagesToTopic(messages, userId, newTopic.threadId, attempt + 1);
    }
  }

  return result;
}

async function forwardMessagesToTarget(messages, userId, target) {
  if (!messages || messages.length === 0) {
    return { ok: false, errorType: 'empty' };
  }
  if (messages.length === 1) {
    const msg = messages[0];
    const payload = {
      chat_id: target.chatId,
      from_chat_id: msg.chat.id,
      message_id: msg.message_id
    };
    if (target.threadId) payload.message_thread_id = target.threadId;

    const forwardReq = await forwardMessage(payload);
    const outcome = await handleSingleForwardResult(forwardReq, msg, target, userId);
    if (outcome.success) {
      return { ok: true, result: forwardReq.result };
    }
    return { ok: false, errorType: outcome.errorType, raw: forwardReq };
  }

  const firstMsg = messages[0];
  const messageIds = messages.map(m => m.message_id);
  const payload = {
    chat_id: target.chatId,
    from_chat_id: firstMsg.chat.id,
    message_ids: messageIds
  };
  if (target.threadId) payload.message_thread_id = target.threadId;

  const forwardReq = await forwardMessagesWithFallback(payload);
  const outcome = await handleBatchForwardResult(forwardReq, messages, target, userId, messageIds.length);
  if (outcome.success) {
    return { ok: true, result: forwardReq.result };
  }
  return { ok: false, errorType: outcome.errorType, raw: forwardReq };
}

async function handleSingleForwardResult(result, msg, target, userId) {
  if (result.ok && result.result && result.result.message_id) {
    await storeForwardMapping(result.result.message_id, msg, target);
    return { success: true };
  }

  if (!result.ok && shouldAttemptCopyFallback(target)) {
    const copyOutcome = await tryCopySingleMessage(msg, target);
    if (copyOutcome.success) {
      return { success: true };
    }
    result = copyOutcome.rawResult || result;
  }

  const errorType = result.errorType || 'unknown';
  if (errorType === 'message_not_found') {
    Logger.warn('message_not_found', { userId, messageId: msg.message_id, target: target.label });
    return { success: true };
  }
  if (errorType === 'thread_not_found' && target.label === 'topic') {
    Logger.warn('topic_thread_not_found', { userId, threadId: target.threadId });
    return { success: false, errorType };
  }
  if (errorType === 'bot_blocked' && target.label === 'admin_dm') {
    Logger.warn('bot_blocked_by_admin', { userId, adminId: ADMIN_UID });
    await sendMessage({
      chat_id: userId,
      text: '⚠️ 消息发送失败：管理员已屏蔽机器人，无法接收消息。'
    });
    return { success: false, errorType };
  }

  await notifyForwardFailure(target, result);
  return { success: false, errorType };
}

async function handleBatchForwardResult(result, messages, target, userId, count) {
  if (result.ok && Array.isArray(result.result)) {
    for (let i = 0; i < messages.length; i++) {
      const forwardedMsg = result.result[i];
      const origMsg = messages[i];
      if (forwardedMsg && forwardedMsg.message_id) {
        await storeForwardMapping(forwardedMsg.message_id, origMsg, target);
      }
    }
    return { success: true };
  }

  if (!result.ok && shouldAttemptCopyFallback(target)) {
    const fallbackResult = await copyMessagesIndividually(messages, target);
    if (fallbackResult.success) {
      return { success: true };
    }
    result = fallbackResult.rawResult || result;
  }

  const errorType = result.errorType || 'unknown';
  if (errorType === 'message_not_found') {
    Logger.warn('batch_messages_not_found', { userId, target: target.label, count });
    return { success: true };
  }
  if (errorType === 'thread_not_found' && target.label === 'topic') {
    Logger.warn('batch_topic_thread_not_found', { userId, target: target.label, threadId: target.threadId });
    return { success: false, errorType };
  }

  await notifyForwardFailure(target, result);
  return { success: false, errorType };
}

async function storeForwardMapping(forwardedMessageId, originalMessage, target = null) {
  if (!forwardedMessageId || !originalMessage) return;
  try {
    await KV.put('msg-map-' + forwardedMessageId, originalMessage.chat.id.toString(), { expirationTtl: 172800 });
    await KV.put('orig-map-' + originalMessage.message_id, forwardedMessageId.toString(), { expirationTtl: 172800 });
    if (target && target.chatId) {
      await KV.put(
        'fwd-loc-' + forwardedMessageId,
        JSON.stringify({ chat_id: target.chatId, thread_id: target.threadId || null }),
        { expirationTtl: 172800 }
      );
    }
  } catch (e) {
    Logger.warn('store_forward_mapping_failed', e, {
      forwardedMessageId,
      originalMessageId: originalMessage.message_id
    });
  }
}

async function notifyForwardFailure(target, result) {
  const recipient = ADMIN_UID || target.chatId;
  const hint = target.label === 'topic' ? '请检查机器人是否为群组管理员，并确认群组已启用话题。' : '';
  await sendMessage({
    chat_id: recipient,
    text: `❌ 转发消息失败：${result.userMessage || result.description || '未知错误'}${hint ? `\n\n${hint}` : ''}`
  });
}

// 处理访客编辑后的消息
function shouldAttemptCopyFallback(target) {
  return target && target.label === 'topic';
}

async function tryCopySingleMessage(msg, target) {
  const payload = {
    chat_id: target.chatId,
    from_chat_id: msg.chat.id,
    message_id: msg.message_id
  };
  if (target.threadId) payload.message_thread_id = target.threadId;

  const copyReq = await requestTelegram('copyMessage', payload);
  if (copyReq.ok && copyReq.result && copyReq.result.message_id) {
    await storeForwardMapping(copyReq.result.message_id, msg, target);
    return { success: true };
  }
  return { success: false, rawResult: copyReq };
}

async function copyMessagesIndividually(messages, target) {
  for (const msg of messages) {
    const payload = {
      chat_id: target.chatId,
      from_chat_id: msg.chat.id,
      message_id: msg.message_id
    };
    if (target.threadId) payload.message_thread_id = target.threadId;

    const copyReq = await requestTelegram('copyMessage', payload);
    if (copyReq.ok && copyReq.result && copyReq.result.message_id) {
      await storeForwardMapping(copyReq.result.message_id, msg, target);
    } else {
      return { success: false, rawResult: copyReq };
    }
  }
  return { success: true };
}

async function handleGuestEditedMessage(message) {
  const origMessageId = message.message_id.toString();
  const chatId = message.chat.id.toString();

  // 查找原始消息转发后的 ID（用于回复引用）
  const forwardedMessageIdRaw = await KV.get('orig-map-' + origMessageId);
  let forwardedMessageId = null;
  let forwardLocation = null;
  if (forwardedMessageIdRaw) {
    const numericId = parseInt(forwardedMessageIdRaw, 10);
    forwardedMessageId = Number.isNaN(numericId) ? forwardedMessageIdRaw : numericId;
    const locRaw = await KV.get('fwd-loc-' + forwardedMessageIdRaw);
    if (locRaw) {
      try {
        forwardLocation = JSON.parse(locRaw);
      } catch (e) {
        Logger.warn('parse_forward_location_failed', e, { forwardedMessageId: forwardedMessageIdRaw });
      }
    }
  }

  // 查找是否已有编辑提示消息
  const editNoticeKey = `edit-notice:${chatId}:${origMessageId}`;
  let existingNotice = null;
  const existingNoticeRaw = await KV.get(editNoticeKey);
  if (existingNoticeRaw) {
    try {
      existingNotice = JSON.parse(existingNoticeRaw);
    } catch (e) {
      existingNotice = { chat_id: ADMIN_UID, message_id: parseInt(existingNoticeRaw, 10) || existingNoticeRaw };
      Logger.warn('parse_edit_notice_failed', e, { editNoticeKey });
    }
  }

  const editNotice = `✏️ ${escapeHtml(message.text || '(无文本内容)')}`;

  if (existingNotice) {
    // 已有编辑提示，尝试更新
    try {
      const editReq = await requestTelegram('editMessageText', {
        chat_id: existingNotice.chat_id || ADMIN_UID,
        message_id: parseInt(existingNotice.message_id),
        text: editNotice,
        parse_mode: 'HTML'
      });

      if (editReq.ok) {
        // 更新成功
        return;
      }
      // 更新失败（可能消息被删除），继续发送新消息
    } catch (e) {
      Logger.warn('update_edit_hint_failed', e);
      // 继续发送新消息
    }
  }

  // 发送新的编辑提示
  const targetChatId = forwardLocation?.chat_id || ADMIN_UID;
  const targetThreadId = forwardLocation?.thread_id || null;
  const sendPayload = {
    chat_id: targetChatId,
    text: editNotice,
    parse_mode: 'HTML'
  };
  const replyToId = forwardedMessageId ? Number(forwardedMessageId) : null;
  if (replyToId) {
    sendPayload.reply_to_message_id = replyToId;
  }
  if (targetThreadId) {
    sendPayload.message_thread_id = targetThreadId;
  }
  const result = await sendMessage(sendPayload);

  // 存储映射关系
  if (result.ok && result.result && result.result.message_id) {
    await KV.put('msg-map-' + result.result.message_id, chatId, { expirationTtl: 172800 });
    // 存储编辑提示消息ID、位置，用于后续更新
    await KV.put(
      editNoticeKey,
      JSON.stringify({
        chat_id: targetChatId,
        message_id: result.result.message_id,
        thread_id: targetThreadId
      }),
      { expirationTtl: 172800 }
    );
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

// ========== 本地题库验证回调处理 ==========

// 处理题库答案回调
async function handleQuizCallback(callbackQuery) {
  const userId = String(callbackQuery.from.id);
  const data = callbackQuery.data;
  const messageId = callbackQuery.message.message_id;
  const chatId = callbackQuery.message.chat.id;

  try {
    // 【并发保护】尝试获取验证锁
    const lockResult = await tryAcquireVerifyLock(userId);
    if (!lockResult.acquired) {
      const waitTime = Math.ceil(lockResult.lockInfo.remainingMs / 1000);
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: `⏳ 验证进行中，请等待 ${waitTime} 秒后再试`,
        show_alert: true
      });
    }

    // 【优化】解析答案索引，严格验证格式
    const parts = data.split(':');
    if (parts.length !== 2) {
      await releaseVerifyLock(userId);
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 无效的数据格式',
        show_alert: true
      });
    }

    const answerIndex = parseInt(parts[1]);
    if (isNaN(answerIndex) || answerIndex < 0 || answerIndex > 3) {
      await releaseVerifyLock(userId);
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '❌ 无效的选项',
        show_alert: true
      });
    }

    // 【优化】检查验证尝试频率限制
    const attemptLimit = checkRateLimit(userId, 'verifyAttempt');
    if (!attemptLimit.allowed) {
      await releaseVerifyLock(userId);
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: `⏳ 尝试过于频繁，请等待 ${attemptLimit.retryAfter} 秒后再试`,
        show_alert: true
      });
    }

    // 验证答案
    const result = await verifyQuizAnswer(userId, answerIndex);

    if (result.success) {
      // 答案正确，标记用户已验证
      const verifiedKey = 'verified-' + userId;
      await KV.put(verifiedKey, 'true', { expirationTtl: VERIFICATION_TTL });
      memSet(verifiedKey, 'true', 5 * 60 * 1000);

      // 添加到已验证用户列表
      const user = callbackQuery.from;
      const userName = user.username || user.first_name || 'Unknown';
      await addVerifiedUser(userId, userName);

      // 缓存用户资料
      await upsertUserProfileFromUpdate(user);

      // 处理暂存的消息
      let pendingResult = { forwarded: 0, failed: 0 };
      try {
        pendingResult = await processPendingMessagesAfterVerification(userId);
        Logger.info('local_quiz_verification_success', { userId, pendingForwarded: pendingResult.forwarded });
      } catch (e) {
        Logger.error('process_pending_messages_failed', e, { userId });
      }

      // 构建成功消息
      let successText = '✅ 验证成功！您现在可以发送消息给管理员了。';
      if (pendingResult.forwarded > 0) {
        successText = `✅ 验证成功！\n\n📩 刚才的 ${pendingResult.forwarded} 条消息已送达管理员。`;
      }

      // 更新消息为成功状态
      try {
        await requestTelegram('editMessageText', {
          chat_id: chatId,
          message_id: messageId,
          text: successText,
          parse_mode: 'HTML',
          reply_markup: { inline_keyboard: [] }
        });
      } catch (e) {
        Logger.error('edit_message_text_failed', e, { userId });
      }

      // 发送欢迎消息（如果没有暂存消息转发）
      if (pendingResult.forwarded === 0) {
        try {
          const welcomeMsg = await getConfig(CONFIG_KEYS.WELCOME_MSG);
          if (welcomeMsg) {
            await sendMessage({
              chat_id: userId,
              text: welcomeMsg
            });
          }
        } catch (e) {
          Logger.error('send_welcome_msg_failed', e, { userId });
        }
      }

      // 记录活跃
      try {
        await recordActiveUser(userId);
      } catch (e) {
        Logger.error('record_active_user_failed', e, { userId });
      }

      await releaseVerifyLock(userId);
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: '验证成功！'
      });
    } else {
      // 答案错误
      if (result.reason === 'expired' || result.reason === 'max_attempts') {
        // 题目过期或尝试次数过多，删除按钮
        try {
          await requestTelegram('editMessageReplyMarkup', {
            chat_id: chatId,
            message_id: messageId,
            reply_markup: { inline_keyboard: [] }
          });
        } catch (e) {
          Logger.error('edit_reply_markup_failed', e, { userId });
        }

        await releaseVerifyLock(userId);
        return requestTelegram('answerCallbackQuery', {
          callback_query_id: callbackQuery.id,
          text: result.message,
          show_alert: true
        });
      }

      // 答案错误但还可以继续尝试
      await releaseVerifyLock(userId);
      return requestTelegram('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: result.message,
        show_alert: true
      });
    }
  } catch (e) {
    Logger.error('handle_quiz_callback_failed', e, { userId });
    try {
      await releaseVerifyLock(userId);
    } catch (e2) {
      Logger.error('release_lock_failed', e2, { userId });
    }
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: '❌ 验证处理出错，请重试',
      show_alert: true
    });
  }
}

// 处理验证模式切换回调
async function handleVerifyModeCallback(callbackQuery) {
  const data = callbackQuery.data;
  const chatId = callbackQuery.message.chat.id;
  const messageId = callbackQuery.message.message_id;

  const newMode = data.split(':')[1];

  // 尝试设置新模式
  const success = await setVerifyMode(newMode);

  if (!success) {
    return requestTelegram('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
      text: '❌ 无法切换到该模式，请确保已配置 Turnstile 密钥',
      show_alert: true
    });
  }

  // 更新菜单显示
  const menu = await generateMainMenu();
  await requestTelegram('editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    text: menu.text,
    parse_mode: 'HTML',
    reply_markup: menu.reply_markup
  });

  return requestTelegram('answerCallbackQuery', {
    callback_query_id: callbackQuery.id,
    text: `已切换到：${getVerifyModeName(newMode)}`
  });
}
