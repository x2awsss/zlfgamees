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
  TWITCH_CLIENT_ID,
  TWITCH_CLIENT_SECRET,
  TWITCH_REDIRECT_URI,
  PORT = 3000,
  SESSION_SECRET = 'change-this-secret',
  ADMIN_PASSWORD_HASH,
  ALLOWED_USERS = '' // أسماء حسابات Kick / Twitch المسموح لها بدخول الألعاب
} = process.env;

// ===== إدارة الوايت لست (الدمج بين الـ .env والتحكم الديناميكي من الأدمن) =====
const envAllowedUsers = ALLOWED_USERS.split(',').map(u => u.trim().toLowerCase()).filter(Boolean);

let customAddedUsers = new Set();
let customRemovedUsers = new Set();

function isUserWhitelisted(username) {
  if (!username) return false;
  const cleanName = username.toLowerCase().trim();

  if (customRemovedUsers.has(cleanName)) return false;
  if (customAddedUsers.has(cleanName)) return true;
  if (envAllowedUsers.length === 0 && customAddedUsers.size === 0) return true;

  return envAllowedUsers.includes(cleanName);
}

// ===== دالة التجديد التلقائي لتوكن Kick (ضمان استمرار العمل مدى الحياة) =====
async function getValidKickAccessToken(userId) {
  const userData = store.getUser ? store.getUser(userId) : null;
  if (!userData) return null;

  // إذا التوكن غير منتهي يتم إرجاعه فوراً
  const now = Math.floor(Date.now() / 1000);
  if (userData.expiresAt && userData.expiresAt > now + 60 && userData.accessToken) {
    return userData.accessToken;
  }

  // في حال انتهاء التوكن يتم التجديد تلقائياً باستخدام refresh_token
  if (userData.refreshToken) {
    try {
      console.log(`🔄 جاري تجديد توكن الحساب (${userData.username}) تلقائياً...`);
      const response = await fetch('https://id.kick.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          refresh_token: userData.refreshToken
        })
      });

      const tokenData = await response.json();
      if (response.ok) {
        // تحديث البيانات في الـ Store
        store.upsertUser(userData, tokenData);
        console.log(`✅ تم تجديد توكن (${userData.username}) بنجاح!`);
        return tokenData.access_token;
      } else {
        console.error('فشل تجديد التوكن تلقائياً:', tokenData);
      }
    } catch (err) {
      console.error('خطأ أثناء طلب تجديد التوكن:', err);
    }
  }

  return userData.accessToken;
}

// ===== إعداد الجلسة (Session) =====
const sessionMiddleware = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
});

app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ===== حماية الصفحات المحمية (الوايت لست) + التحقق الفوري من حظر المنصة =====
const PROTECTED_PAGES = ['/roulette', '/countrywar', '/personas', '/drawshow', '/colorsgame'];

function stripHtmlExt(p) {
  return p.replace(/\.html$/i, '');
}

app.use((req, res, next) => {
  const normalizedPath = stripHtmlExt(req.path);

  // 1. الفحص الشامل للحظر من المنصة
  if (req.session && req.session.user) {
    const currentUserId = String(req.session.user.id || req.session.user.user_id || '');
    if (bannedUsers.has(currentUserId)) {
      req.session.destroy();
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

  // 2. حماية الصفحات الخاصة بالألعاب فقط (الوايت لست)
  if (!PROTECTED_PAGES.includes(normalizedPath)) {
    return next();
  }

  if (!req.session.user) {
    return res.redirect('/logintab.html');
  }

  const username = (req.session.user.name || req.session.user.username || '').toString();

  if (!isUserWhitelisted(username)) {
    return res.status(403).send(`
      <div style="font-family:sans-serif; background:#050816; color:#fff; height:100vh; display:flex; align-items:center; justify-content:center; text-align:center; direction:rtl;">
        <div>
          <h1 style="color:#f87171; font-size:2rem; margin-bottom:12px;">🚫 غير مصرح لك بالدخول</h1>
          <p style="color:#929dae; font-size:1.1rem; margin-bottom:20px;">حسابك (${username}) غير مسموح له بالوصول لهذه اللعبة.</p>
          <a href="/logout" style="color:#3b82f6; text-decoration:none; background:rgba(59,130,246,0.1); padding:10px 20px; border-radius:50px; border:1px solid rgba(59,130,246,0.3);">تسجيل خروج وتجربة حساب آخر</a>
        </div>
      </div>
    `);
  }

  next();
});

// ممر خاص بالـ Real-time لطرد المستخدم حياً عند استدعائه
app.get('/api/check-ban-status', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ banned: false, loggedIn: false });
  }
  const currentUserId = String(req.session.user.id || req.session.user.user_id || '');
  const isBanned = bannedUsers.has(currentUserId);
  
  if (isBanned) {
    req.session.destroy();
  }
  
  res.json({ banned: isBanned, loggedIn: true });
});

// تشغيل صفحات الـ HTML بدون امتداد
app.use((req, res, next) => {
  if (req.path === '/' || req.path.includes('.')) {
    return next();
  }
  const htmlPath = path.join(__dirname, 'Public', req.path + '.html');
  if (fs.existsSync(htmlPath)) {
    return res.sendFile(htmlPath);
  }
  next();
});

app.use(express.static(path.join(__dirname, 'Public')));

app.get('/', (req, res) => {
  res.redirect('/zlf');
});

// دوال مساعدة لـ PKCE
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

// =====================================================
// ==================== KICK AUTH =====================
// =====================================================

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
    
    if (profile) {
      const pId = String(profile.id || profile.user_id || '');
      if (bannedUsers.has(pId)) {
        return res.status(403).send('🚫 حسابك محظور من دخول هذه المنصة.');
      }
      
      profile.provider = 'kick';
      profile.name = profile.name || profile.username;
      profile.profile_picture = profile.profile_picture || profile.avatar;

      // 🔑 طباعة التوكنات في الـ Console والـ Logs لنسخها احتياطياً
      console.log(`\n================ NEW LOGIN: ${profile.name} ================`);
      console.log(`ACCESS_TOKEN: ${tokenData.access_token}`);
      console.log(`REFRESH_TOKEN: ${tokenData.refresh_token}`);
      console.log(`EXPIRES_IN: ${tokenData.expires_in} seconds`);
      console.log(`==========================================================\n`);
    }

    req.session.user = profile;

    if (profile) {
      store.upsertUser(profile, tokenData);
    }

    res.redirect('/zlf');
  } catch (err) {
    console.error(err);
    res.status(500).send('حدث خطأ أثناء تسجيل الدخول عبر Kick.');
  }
});

// =====================================================
// =================== TWITCH AUTH ====================
// =====================================================

app.get('/login/twitch', (req, res) => {
  const state = base64url(crypto.randomBytes(16));
  req.session.twitchState = state;

  const scopes = 'user:read:email';
  const twitchAuthUrl = new URL('https://id.twitch.tv/oauth2/authorize');
  twitchAuthUrl.searchParams.set('response_type', 'code');
  twitchAuthUrl.searchParams.set('client_id', TWITCH_CLIENT_ID);
  twitchAuthUrl.searchParams.set('redirect_uri', TWITCH_REDIRECT_URI || 'http://localhost:3000/auth/twitch/callback');
  twitchAuthUrl.searchParams.set('scope', scopes);
  twitchAuthUrl.searchParams.set('state', state);

  res.redirect(twitchAuthUrl.toString());
});

app.get('/auth/twitch/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send('لم يتم استلام كود التفويض من Twitch.');
  }

  if (!state || state !== req.session.twitchState) {
    return res.status(400).send('حالة الطلب (state) غير متطابقة. حاول تسجيل الدخول من جديد.');
  }

  try {
    const redirectUri = TWITCH_REDIRECT_URI || 'http://localhost:3000/auth/twitch/callback';
    
    const tokenRes = await fetch('https://id.twitch.tv/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri
      })
    });

    const tokenData = await tokenRes.json();

    if (!tokenRes.ok) {
      console.error('Twitch Token Exchange Failed:', tokenData);
      return res.status(400).send('فشل استبدال الكود بتوكن مع تويتش.');
    }

    const userRes = await fetch('https://api.twitch.tv/helix/users', {
      headers: {
        'Client-ID': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });

    const userData = await userRes.json();
    const rawTwitchUser = userData?.data?.[0];

    if (!rawTwitchUser) {
      return res.status(400).send('لم يتم العثور على بيانات المستخدم في تويتش.');
    }

    const profile = {
      id: rawTwitchUser.id,
      user_id: rawTwitchUser.id,
      name: rawTwitchUser.display_name || rawTwitchUser.login,
      username: rawTwitchUser.login,
      profile_picture: rawTwitchUser.profile_image_url,
      email: rawTwitchUser.email,
      provider: 'twitch'
    };

    if (bannedUsers.has(String(profile.id))) {
      return res.status(403).send('🚫 حسابك محظور من دخول هذه المنصة.');
    }

    req.session.accessToken = tokenData.access_token;
    req.session.user = profile;

    res.redirect('/zlf');
  } catch (err) {
    console.error('Twitch Login Error:', err);
    res.status(500).send('حدث خطأ أثناء تسجيل الدخول عبر Twitch.');
  }
});

// =====================================================
// ==================== APIs البيانات ==================
// =====================================================

// 🚀 مسار الترحيب التلقائي المستدعى من zlf.html مباشرة
app.post('/api/welcome', async (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'غير مسجل الدخول' });
  }

  const userId = String(req.session.user.id || req.session.user.user_id || '');
  const username = req.session.user.name || req.session.user.username || '';

  if (!userId) {
    return res.status(400).json({ error: 'تعذر تحديد معرّف المستخدم' });
  }

  try {
    await getValidKickAccessToken(userId);
    const welcomeMessage = `يا هلا ومسهلا بـ ${username} في منصة زلف! 🚀✨`;
    const result = await sendChatMessage(userId, welcomeMessage, { asBot: true });
    res.json({ ok: true, result });
  } catch (err) {
    console.error('خطأ في إرسال الترحيب تلقائياً:', err.message);
    res.status(500).json({ error: err.message });
  }
});

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

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/logintab.html'));
});

// =====================================================
// ===============  تاب الأدمن وبقية الـ APIs ===========
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

app.get('/admin/api/whitelist', requireAdmin, (req, res) => {
  const currentList = Array.from(new Set([...envAllowedUsers, ...customAddedUsers]))
    .filter(u => !customRemovedUsers.has(u));
  res.json({ whitelist: currentList });
});

app.post('/admin/api/whitelist/add', requireAdmin, (req, res) => {
  const { username } = req.body;
  if (!username || !username.trim()) return res.status(400).json({ error: 'لازم تحدد اسم اليوزر' });
  
  const cleanName = username.trim().toLowerCase();
  customRemovedUsers.delete(cleanName);
  customAddedUsers.add(cleanName);
  
  console.log(`✅ [Whitelist Add] تم إضافة اليوزر: ${cleanName} للوايت لست من لوحة الأدمن.`);
  res.json({ ok: true, message: 'تم إضافة المستخدم بنجاح' });
});

app.post('/admin/api/whitelist/remove', requireAdmin, (req, res) => {
  const { username } = req.body;
  if (!username || !username.trim()) return res.status(400).json({ error: 'لازم تحدد اسم اليوزر' });
  
  const cleanName = username.trim().toLowerCase();
  customAddedUsers.delete(cleanName);
  customRemovedUsers.add(cleanName);
  
  console.log(`🗑️ [Whitelist Remove] تم إزالة اليوزر: ${cleanName} من الوايت لست من لوحة الأدمن.`);
  res.json({ ok: true, message: 'تم إزالة المستخدم بنجاح' });
});

app.post('/admin/api/site-ban', requireAdmin, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'لازم تحدد ID المستخدم' });
  
  const targetId = String(userId);
  bannedUsers.add(targetId);

  if (req.sessionStore && typeof req.sessionStore.all === 'function') {
    req.sessionStore.all((err, sessions) => {
      if (!err && sessions) {
        Object.keys(sessions).forEach((sid) => {
          const sess = sessions[sid];
          if (sess.user) {
            const uId = String(sess.user.id || sess.user.user_id || '');
            if (uId === targetId) {
              req.sessionStore.destroy(sid, () => {});
            }
          }
        });
      }
    });
  }

  console.log(`🚫 [Platform Ban] تم حظر وقطع جلسة المستخدم ID: ${targetId} فوراً.`);
  res.json({ ok: true, message: 'تم الحظر والطرد الفوري من الموقع' });
});

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
    // التأكد من تجديد التوكن قبل الإرسال
    await getValidKickAccessToken(userId);
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
    await getValidKickAccessToken(broadcasterUserId);
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
    await getValidKickAccessToken(broadcasterUserId);
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
    await getValidKickAccessToken(broadcasterUserId);
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
