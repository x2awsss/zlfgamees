const fs = require('fs');
const path = require('path');

// ⚠️ هذا الملف يخزن التوكنات الحقيقية لكل مستخدم رابط حسابه معك.
// تأكد إنه داخل .gitignore ولا ترفعه لأي مكان عام أبداً.
const DB_PATH = path.join(__dirname, '..', 'data', 'users.json');
const CONFIG_PATH = path.join(__dirname, '..', 'data', 'config.json');

function ensureDb() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, '[]', 'utf8');
}

function loadUsers() {
  ensureDb();
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (err) {
    console.error('تعذر قراءة قاعدة بيانات المستخدمين، راح نبدأ من جديد:', err);
    return [];
  }
}

function saveUsers(users) {
  ensureDb();
  fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2), 'utf8');
}

// يستخدم بعد نجاح OAuth: يحفظ أو يحدّث بيانات المستخدم وتوكناته
function upsertUser(profile, tokens) {
  const users = loadUsers();
  const idx = users.findIndex((u) => String(u.user_id) === String(profile.user_id));
  const now = new Date().toISOString();

  const record = {
    user_id: profile.user_id,
    username: profile.name || profile.username || 'مستخدم بدون اسم',
    profile_picture: profile.profile_picture || null,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: Date.now() + Number(tokens.expires_in || 0) * 1000,
    linked_at: idx === -1 ? now : users[idx].linked_at,
    last_login_at: now
  };

  if (idx === -1) {
    users.push(record);
  } else {
    users[idx] = { ...users[idx], ...record };
  }

  saveUsers(users);
  return record;
}

// قائمة مختصرة للأدمن — ما نرجع التوكنات هنا أبداً
function listUsers() {
  return loadUsers().map((u) => ({
    user_id: u.user_id,
    username: u.username,
    profile_picture: u.profile_picture,
    linked_at: u.linked_at,
    last_login_at: u.last_login_at
  }));
}

// السجل الكامل (يستخدم داخلياً فقط عشان الإرسال، ما يطلع للواجهة)
function getUserById(id) {
  return loadUsers().find((u) => String(u.user_id) === String(id));
}

function updateTokens(id, tokens) {
  const users = loadUsers();
  const idx = users.findIndex((u) => String(u.user_id) === String(id));
  if (idx === -1) return null;
  users[idx].access_token = tokens.access_token;
  if (tokens.refresh_token) users[idx].refresh_token = tokens.refresh_token;
  users[idx].expires_at = Date.now() + Number(tokens.expires_in || 0) * 1000;
  saveUsers(users);
  return users[idx];
}

function removeUser(id) {
  const users = loadUsers().filter((u) => String(u.user_id) !== String(id));
  saveUsers(users);
}

// ===== إعدادات عامة (حالياً بس: أي حساب مرتبط هو "بوت الموقع") =====
function ensureConfig() {
  const dir = path.dirname(CONFIG_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(CONFIG_PATH)) fs.writeFileSync(CONFIG_PATH, '{}', 'utf8');
}

function getConfig() {
  ensureConfig();
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (err) {
    return {};
  }
}

function saveConfig(config) {
  ensureConfig();
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
}

// يحدد أي حساب مرتبط (لازم يكون سجل دخول عندك مرة قبل) هو حساب بوت الموقع الرسمي
function setBotAccount(userId) {
  const user = getUserById(userId);
  if (!user) throw new Error('هذا الحساب ما سجل دخول بالموقع قبل — سجّله دخول أول');
  const config = getConfig();
  config.botAccountUserId = String(userId);
  saveConfig(config);
  return user;
}

function clearBotAccount() {
  const config = getConfig();
  delete config.botAccountUserId;
  saveConfig(config);
}

function getBotAccountId() {
  return getConfig().botAccountUserId || null;
}

// معلومات مختصرة عن بوت الموقع الحالي (للعرض بالواجهة)
function getBotAccountInfo() {
  const id = getBotAccountId();
  if (!id) return null;
  const user = getUserById(id);
  if (!user) return null;
  return { user_id: user.user_id, username: user.username, profile_picture: user.profile_picture };
}

module.exports = {
  upsertUser,
  listUsers,
  getUserById,
  updateTokens,
  removeUser,
  setBotAccount,
  clearBotAccount,
  getBotAccountId,
  getBotAccountInfo
};