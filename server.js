require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fetch = require('node-fetch');

const store = require('./lib/store');
const { sendChatMessage, banUser, unbanUser, updateChannel } = require('./lib/kick');
const { verifyPassword } = require('./lib/auth');

const app = express();

// قائمة لحفظ مستخدمي الموقع المحظورين (Platform Banned)
let bannedUsers = new Set();

const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  PORT = 3000,
  SESSION_SECRET = 'change-this-secret',
  ADMIN_PASSWORD_HASH,
  ALLOWED_USERS = '' // أسماء حسابات Kick المسموح لها بدخول الألعاب، مفصولة بفاصلة. اتركهافاضية للسماح للجميع
} = process.env;

// تحويل قائمة الأسماء المسموحة لأحرف صغيرة عشان المقارنة ما تتأثر بحالة الأحرف
const allowedUsersList = ALLOWED_USERS.split(',').map(u => u.trim().toLowerCase()).filter(Boolean);

// ===== إعداد الجلسة (Session) لتخزين بيانات المستخدم بعد تسجيل الدخول =====
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' } // خليها secure:true عند النشر على https
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ===== حماية الصفحات المحمية (الوايت لست) + التحقق الفوري والشامل من حظر المنصة (Site Ban) =====
// تم إضافة /colorsgame هنا لحماية لعبة الألوان بالوايت لست
const PROTECTED_PAGES = ['/roulette', '/countrywar', '/personas', '/drawshow', '/colorsgame'];

function stripHtmlExt(p) {
  return p.replace(/\.html$/i, '');
}

// تعديل خطاف الفحص الشامل: الحظر يطبق على كل الصفحات بدون استثناء
app.use((req, res, next) => {
  const normalizedPath = stripHtmlExt(req.path);

  // 1. الفحص الشامل: لو اليوزر مسجل دخول ومحظور، يقفل عليه الموقع كامل فوراً وينطرد من أي صفحة
  if (req.session.user) {
    const currentUserId = String(req.session.user.id || req.session.user.user_id || '');
    if (bannedUsers.has(currentUserId)) {
      return res.status(403).send(`
        <div style="font-family:sans-serif; background:#050816; color:#fff; height:100vh; display:flex; align-items:center; justify-content:center; text-align:center; direction:rtl;">
          <div>
            <h1 style="color:#ff5c5c; font-size:2.5rem; margin-bottom:10px;">🚫 تم حظرك من الموقع</h1>
            <p style="color:#929dae; font-size:1.1rem;">لقد تم إنهاء صلاحية وصول حسابك إلى هذه المنصة بقرار من الإدارة.</p>
          </div>
        </div>
      `);
    }
  }

  // 2. حماية الصفحات الخاصة بالألعاب فقط لمنع غير المصرح لهم (الوايت لست)
  if (!PROTECTED_PAGES.includes(normalizedPath)) {
    return next(); // الصفحات المفتوحة (مثل zlf) تكمل طبيعي لو مو محظور الحساب
  }

  if (!req.session.user) {
    return res.redirect('/logintab.html');
  }

  // لو القائمة فاضية بالكامل، نسمح لأي حد مسجل دخول (وضع مفتوح مؤقت)
  if (allowedUsersList.length === 0) {
    return next();
  }

  const username = (req.session.user.name || '').toString().toLowerCase();
  if (!allowedUsersList.includes(username)) {
    return res.status(403).send(`
      <div style="font-family:sans-serif; background:#050816; color:#fff; height:100vh; display:flex; align-items:center; justify-content:center; text-align:center; direction:rtl;">
        <div>
          <h1 style="color:#f87171; font-size:2rem; margin-bottom:12px;">🚫 غير مصرح لك بالدخول</h1>
          <p style="color:#929dae; font-size:1.1rem; margin-bottom:20px;">حسابك (${req.session.user.name}) غير مسموح له بالوصول لهذه اللعبة.</p>
          <a href="/logout" style="color:#3b82f6; text-decoration:none; background:rgba(59,130,246,0.1); padding:10px 20px; border-radius:50px; border:1px solid rgba(59,130,246,0.3);">تسجيل خروج وتجربة حساب آخر</a>
        </div>
      </div>
    `);
  }

  next();
});

// ممر خاص بالـ Real-time لطرد المستخدم حياً عند استدعائه
app.get('/api/check-ban-status', (req, res) => {
  if (!req.session.user) return res.json({ banned: false });
  const currentUserId = String(req.session.user.id || req.session.user.user_id || '');
  res.json({ banned: bannedUsers.has(currentUserId) });
});

// ===== يخلي أي صفحة HTML تشتغل بدون كتابة .html بالرابط ويجبر عرضها بدلاً من تحميلها =====
app.use((req, res, next) => {
  if (req.path === '/' || req.path.includes('.')) {
    return next(); // فيه امتداد أصلاً أو الصفحة الرئيسية، تجاهل
  }
  const htmlPath = path.join(__dirname, 'Public', req.path + '.html');
  if (fs.existsSync(htmlPath)) {
    return res.sendFile(htmlPath); // يرسل ملف الـ HTML مباشرة لفتحه في المتصفح
  }
  next();
});

app.use(express.static(path.join(__dirname, 'Public'))); // مجلد الملفات العامة

// ===== 0) المسار الرئيسي: التوجيه المباشر للواجهة الجديدة zlf بدون .html =====
app.get('/', (req, res) => {
  res.redirect('/zlf');
});

// ===== دوال مساعدة لـ PKCE =====
function base64url(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateCodeVerifier() {
  return base64url(crypto.randomBytes(32));
}

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64url(hash);
}

// ===== 1) صفحة تبدأ تسجيل الدخول =====
app.get('/login', (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = base64url(crypto.randomBytes(16));

  req.session.codeVerifier = codeVerifier;
  req.session.oauthState = state;

  const scopes = [
    'user:read',
    'chat:write',
    'channel:read',
    'channel:write',
    'moderation:ban',
    'moderation:chat_message:manage'
  ].join(' ');

  const authUrl = new URL('https://id.kick.com/oauth/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', scopes);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);

  res.redirect(authUrl.toString());
});

// ===== 2) نقطة الرجوع (Callback) =====
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send('لم يتم استلام كود التفويض من Kick.');
  }

  if (!state || state !== req.session.oauthState) {
    return res.status(400).send('حالة الطلب (state) غير متطابقة. حاول تسجيل الدخول من جديد.');
  }

  const codeVerifier = req.session.codeVerifier;

  try {
    const tokenRes = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code_verifier: codeVerifier,
        code
      })
    });

    const tokenData = await tokenRes.json();

    if (!tokenRes.ok) {
      console.error('Token exchange failed:', tokenData);
      return res.status(400).send('فشل استبدال الكود بتوكن. تحقق من الطرفية للتفاصيل.');
    }

    req.session.accessToken = tokenData.access_token;
    req.session.refreshToken = tokenData.refresh_token;
    req.session.expiresIn = tokenData.expires_in;

    const userRes = await fetch('https://api.kick.com/public/v1/users', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();
    const profile = userData?.data?.[0] || null;
    req.session.user = profile;

    if (profile) {
      store.upsertUser(profile, tokenData);
    }

    res.redirect('/zlf');
  } catch (err) {
    console.error(err);
    res.status(500).send('حدث خطأ أثناء تسجيل الدخول.');
  }
});

// ===== 3) APIs جلب البيانات =====
app.get('/api/chatroom', async (req, res) => {
  if (!req.session.user || !req.session.accessToken) {
    return res.status(401).json({ error: 'يجب تسجيل الدخول أولاً' });
  }
  try {
    const channelsRes = await fetch('https://api.kick.com/public/v1/channels', {
      headers: { Authorization: `Bearer ${req.session.accessToken}` }
    });
    const channelsData = await channelsRes.json();
    const slug = channelsData?.data?.[0]?.slug;

    if (!slug) {
      return res.status(404).json({ error: 'ما قدرنا نحدد اسم القناة (slug)' });
    }

    const response = await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'application/json',
        'Accept-Language': 'ar,en;q=0.9'
      }
    });

    if (!response.ok) {
      return res.status(502).json({ error: `Kick رفض الطلب (حالة ${response.status})` });
    }

    const data = await response.json();
    const chatroomId = data?.chatroom?.id;

    if (!chatroomId) {
      return res.status(404).json({ error: 'ما لقينا رقم غرفة الشات بالاستجابة' });
    }

    res.json({ chatroomId, slug });
  } catch (err) {
    console.error('chatroom lookup error:', err);
    res.status(500).json({ error: 'خطأ أثناء جلب بيانات القناة' });
  }
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ loggedIn: false });
  }
  
  const currentUserId = String(req.session.user.id || req.session.user.user_id || '');
  const updatedUser = { ...req.session.user, is_site_banned: bannedUsers.has(currentUserId) };
  
  res.json({ loggedIn: true, user: updatedUser });
});

// ===== 4) تسجيل الخروج =====
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/logintab.html'));
});

// =====================================================
// ===============  تاب الأدمن وبقية الـ APIs  ===========
// =====================================================

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  return res.redirect('/admin/login');
}

app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin', 'login.html'));
});

app.post('/admin/login', (req, res) => {
  const { password } = req.body;

  if (!ADMIN_PASSWORD_HASH) {
    return res.status(500).send('السيرفر ما فيه ADMIN_PASSWORD_HASH بملف .env.');
  }

  if (verifyPassword(password || '', ADMIN_PASSWORD_HASH)) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }

  res.status(401).send('كلمة المرور غير صحيحة. <a href="/admin/login">حاول مرة أخرى</a>');
});

app.get('/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.redirect('/admin/login');
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin', 'dashboard.html'));
});

app.get('/admin/api/users', requireAdmin, (req, res) => {
  const usersList = store.listUsers().map(u => {
    const uId = String(u.id || u.user_id || '');
    return { ...u, is_site_banned: bannedUsers.has(uId) };
  });
  res.json({ users: usersList });
});

// ⭐ API تنفيذ حظر المستخدم من المنصة بالكامل
app.post('/admin/api/site-ban', requireAdmin, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'لازم تحدد ID المستخدم' });
  
  bannedUsers.add(String(userId));
  console.log(`🚫 [Platform Ban] تم حظر المستخدم ذو الـ ID: ${userId} من دخول الموقع.`);
  res.json({ ok: true, message: 'تم الحظر من الموقع' });
});

// ⭐ API فك حظر المستخدم من المنصة
app.post('/admin/api/site-unban', requireAdmin, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'لازم تحدد ID المستخدم' });
  
  bannedUsers.delete(String(userId));
  console.log(`✅ [Platform Unban] تم فك حظر المستخدم ذو الـ ID: ${userId}`);
  res.json({ ok: true, message: 'تم فك الحظر من الموقع' });
});

app.post('/admin/api/send-message', requireAdmin, async (req, res) => {
  const { userId, message, asBot } = req.body;
  if (!userId || !message || !String(message).trim()) {
    return res.status(400).json({ error: 'لازم تحدد المستخدم ونص الرسالة' });
  }
  try {
    const result = await sendChatMessage(userId, String(message).trim(), { asBot: !!asBot });
    res.json({ ok: true, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/ban', requireAdmin, async (req, res) => {
  const { broadcasterUserId, targetUserId, reason, durationMinutes } = req.body;
  if (!broadcasterUserId || !targetUserId) {
    return res.status(400).json({ error: 'لازم تحدد البثّاث والمستخدم المستهدف' });
  }
  try {
    const result = await banUser(broadcasterUserId, targetUserId, reason, durationMinutes);
    res.json({ ok: true, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/unban', requireAdmin, async (req, res) => {
  const { broadcasterUserId, targetUserId } = req.body;
  if (!broadcasterUserId || !targetUserId) {
    return res.status(400).json({ error: 'لازم تحدد البثّاث والمستخدم المستهدف' });
  }
  try {
    const result = await unbanUser(broadcasterUserId, targetUserId);
    res.json({ ok: true, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/update-channel', requireAdmin, async (req, res) => {
  const { broadcasterUserId, streamTitle, categoryId } = req.body;
  if (!broadcasterUserId) {
    return res.status(400).json({ error: 'لازم تحدد البثّاث' });
  }
  try {
    const result = await updateChannel(broadcasterUserId, { streamTitle, categoryId });
    res.json({ ok: true, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/api/bot-account', requireAdmin, (req, res) => {
  res.json({ bot: store.getBotAccountInfo() });
});

app.post('/admin/api/bot-account', requireAdmin, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'لازم تحدد userId' });
  try {
    store.setBotAccount(userId);
    res.json({ ok: true, bot: store.getBotAccountInfo() });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/admin/api/bot-account', requireAdmin, (req, res) => {
  store.clearBotAccount();
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`السيرفر شغال على http://localhost:${PORT}`);
  console.log(`لوحة الأدمن: http://localhost:${PORT}/admin/login`);
});
