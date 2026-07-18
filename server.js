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

const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  PORT = 3000,
  SESSION_SECRET = 'change-this-secret',
  ADMIN_PASSWORD_HASH,
  ALLOWED_USERS = '' // أسماء حسابات Kick المسموح لها بدخول الألعاب، مفصولة بفاصلة. اتركها فاضية للسماح للجميع
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

// ===== حماية الصفحات المحمية: تتحقق من تسجيل الدخول + إن الحساب موجود بقائمة المصرح لهم =====
// التعديل هنا: شلنا '/ibra' عشان تفتح الصفحة للجميع بدون تحويل تلقائي، وبقت الحماية لـ '/roulette' فقط
const PROTECTED_PAGES = ['/roulette']; 

function stripHtmlExt(p) {
  return p.replace(/\.html$/i, '');
}

app.use((req, res, next) => {
  const normalizedPath = stripHtmlExt(req.path);

  if (!PROTECTED_PAGES.includes(normalizedPath)) {
    return next(); // صفحات ثانية (زي logintab و ibra) تفضل مفتوحة للجميع
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
          <h1 style="color:#f87171;">🚫 غير مصرح لك بالدخول</h1>
          <p style="color:#929dae;">حسابك (${req.session.user.name}) مو ضمن قائمة الحسابات المسموح لها بهذه اللعبة.</p>
          <a href="/logout" style="color:#3b82f6;">تسجيل خروج وتجربة حساب ثاني</a>
        </div>
      </div>
    `);
  }

  next();
});

// ===== يخلي أي صفحة HTML تشتغل بدون كتابة .html بالرابط =====
app.use((req, res, next) => {
  if (req.path === '/' || req.path.includes('.')) {
    return next(); // فيه امتداد أصلاً (زي .css أو .js) أو الصفحة الرئيسية، تجاهل
  }
  const htmlPath = path.join(__dirname, 'Public', req.path + '.html');
  if (fs.existsSync(htmlPath)) {
    return res.sendFile(htmlPath);
  }
  next();
});

app.use(express.static('Public')); // مجلد الملفات العامة

// ===== 0) المسار الرئيسي: التوجيه المباشر للواجهة بدون .html ليكون الرابط نظيفاً =====
app.get('/', (req, res) => {
  res.redirect('/ibra');
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

// ===== 1) صفحة تبدأ تسجيل الدخول: توجّه المستخدم لكيك =====
app.get('/login', (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = base64url(crypto.randomBytes(16));

  // نخزن verifier و state بالجلسة عشان نتحقق منها بعد الرجوع
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

// ===== 2) نقطة الرجوع (Callback): كيك يرجّع المستخدم هنا بعد الموافقة =====
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send('لم يتم استلام كود التفويض من Kick.');
  }

  // تحقق من الـ state لمنع هجمات CSRF
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

    // نخزن التوكنات بالجلسة (للطلبات الفورية بنفس الجلسة)
    req.session.accessToken = tokenData.access_token;
    req.session.refreshToken = tokenData.refresh_token;
    req.session.expiresIn = tokenData.expires_in;

    // نجيب بيانات المستخدم مباشرة عشان نعرضها بالواجهة
    const userRes = await fetch('https://api.kick.com/public/v1/users', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();
    const profile = userData?.data?.[0] || null;
    req.session.user = profile;

    // ⭐ نخزن المستخدم وتوكناته بشكل دائم عشان الأدمن يقدر يشوفه ويرسله رسايل لاحقاً
    if (profile) {
      store.upsertUser(profile, tokenData);
    }

    // التعديل هنا: التوجيه للرابط النظيف بدون .html بعد الدخول بنجاح
    res.redirect('/ibra');
  } catch (err) {
    console.error(err);
    res.status(500).send('حدث خطأ أثناء تسجيل الدخول.');
  }
});

// ===== 3) API بسيط يرجع بيانات المستخدم الحالي للواجهة (index.html يستدعيه) =====
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

    console.log('🔍 [chatroom lookup] slug الصحيح من الـ API الرسمي:', slug);

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

    console.log('🔍 [chatroom lookup] حالة استجابة الرابط الغير رسمي:', response.status);

    if (!response.ok) {
      const errText = await response.text();
      console.log('🔍 [chatroom lookup] نص الخطأ:', errText.slice(0, 300));
      return res.status(502).json({ error: `Kick رفض الطلب (حالة ${response.status}) — راجع الطرفية` });
    }

    const data = await response.json();
    const chatroomId = data?.chatroom?.id;
    console.log('🔍 [chatroom lookup] رقم غرفة الشات:', chatroomId);

    if (!chatroomId) {
      console.log('🔍 [chatroom lookup] الاستجابة كاملة:', JSON.stringify(data).slice(0, 500));
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
  res.json({ loggedIn: true, user: req.session.user });
});

// ===== 4) تسجيل الخروج =====
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/logintab.html'));
});

// =====================================================
// ===============  تاب الأدمن (خاص فيك بس)  ===========
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
    return res.status(500).send('السيرفر ما فيه ADMIN_PASSWORD_HASH بملف .env. شغّل: node scripts/hash-password.js "كلمة-سرك"');
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

// قائمة المستخدمين الرابطين حساباتهم (بدون توكنات — بس بيانات عرض)
app.get('/admin/api/users', requireAdmin, (req, res) => {
  res.json({ users: store.listUsers() });
});

// إرسال رسالة بشات مستخدم معيّن، باستخدام التوكن اللي وافق عليه وقت الربط
app.post('/admin/api/send-message', requireAdmin, async (req, res) => {
  const { userId, message, asBot } = req.body;

  if (!userId || !message || !String(message).trim()) {
    return res.status(400).json({ error: 'لازم تحدد المستخدم ونص الرسالة' });
  }

  try {
    const result = await sendChatMessage(userId, String(message).trim(), { asBot: !!asBot });
    res.json({ ok: true, result });
  } catch (err) {
    console.error('send-message error:', err);
    res.status(500).json({ error: err.message });
  }
});

// حظر / تايم آوت مستخدم من شات أحد البثّاثين الرابطين حسابهم
app.post('/admin/api/ban', requireAdmin, async (req, res) => {
  const { broadcasterUserId, targetUserId, reason, durationMinutes } = req.body;

  if (!broadcasterUserId || !targetUserId) {
    return res.status(400).json({ error: 'لازم تحدد البثّاث والمستخدم المستهدف' });
  }

  try {
    const result = await banUser(broadcasterUserId, targetUserId, reason, durationMinutes);
    res.json({ ok: true, result });
  } catch (err) {
    console.error('ban error:', err);
    res.status(500).json({ error: err.message });
  }
});

// فك الحظر
app.post('/admin/api/unban', requireAdmin, async (req, res) => {
  const { broadcasterUserId, targetUserId } = req.body;

  if (!broadcasterUserId || !targetUserId) {
    return res.status(400).json({ error: 'لازم تحدد البثّاث والمستخدم المستهدف' });
  }

  try {
    const result = await unbanUser(broadcasterUserId, targetUserId);
    res.json({ ok: true, result });
  } catch (err) {
    console.error('unban error:', err);
    res.status(500).json({ error: err.message });
  }
});

// تعديل عنوان البث / الكاتيجوري لقناة أحد البثّاثين
app.post('/admin/api/update-channel', requireAdmin, async (req, res) => {
  const { broadcasterUserId, streamTitle, categoryId } = req.body;

  if (!broadcasterUserId) {
    return res.status(400).json({ error: 'لازم تحدد البثّاث' });
  }

  try {
    const result = await updateChannel(broadcasterUserId, { streamTitle, categoryId });
    res.json({ ok: true, result });
  } catch (err) {
    console.error('update-channel error:', err);
    res.status(500).json({ error: err.message });
  }
});

// عرض حساب بوت الموقع الحالي (لو موجود)
app.get('/admin/api/bot-account', requireAdmin, (req, res) => {
  res.json({ bot: store.getBotAccountInfo() });
});

// تحديد أي حساب مرتبط يكون هو بوت الموقع الرسمي (لازم يكون سجل دخول عندك مرة قبل)
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

// إلغاء تحديد بوت الموقع
app.delete('/admin/api/bot-account', requireAdmin, (req, res) => {
  store.clearBotAccount();
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`السيرفر شغال على http://localhost:${PORT}`);
  console.log(`لوحة الأدمن: http://localhost:${PORT}/admin/login`);
});
