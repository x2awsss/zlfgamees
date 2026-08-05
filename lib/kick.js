const fetch = require('node-fetch');
const store = require('./store');

// نفس أسماء متغيرات البيئة المستخدمة بملف الـ OAuth الأول
const CLIENT_ID = process.env.KICK_CLIENT_ID;
const CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;

// يجدد التوكن تلقائياً لو باقي أقل من دقيقة على انتهائه
async function refreshIfNeeded(user) {
  const bufferMs = 60 * 1000;
  if (Date.now() < user.expires_at - bufferMs) return user;

  const res = await fetch('https://id.kick.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: user.refresh_token
    })
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    console.error('[Kick] فشل تجديد التوكن — status:', res.status, 'response:', JSON.stringify(data));
    throw new Error('فشل تجديد التوكن — المستخدم غالباً سحب الصلاحية من حسابه بـ Kick: ' + JSON.stringify(data));
  }

  return store.updateTokens(user.user_id, data);
}

// يرسل رسالة داخل شات قناة "targetUserId" — إما باسم صاحب القناة نفسه، أو باسم حساب بوت الموقع
// (حساب البوت لازم يكون سجل دخول عندك مرة قبل وتحدد كـ"بوت الموقع" من لوحة التحكم)
// شروط Kick الرسمية لإرسال type:'bot':
//  1) حساب البوت لازم يكون عمل نفس الـ OAuth Authorization Code flow وعنده scope: chat:write
//  2) حساب البوت لازم يكون متابع/منضم أو غير محظور بالقناة الهدف (وإلا API يرجع خطأ صريح)
//  3) senderUser هو حساب البوت نفسه — broadcaster_user_id يبقى ID صاحب القناة المُرسَل لها
async function sendChatMessage(targetUserId, message, { asBot = false } = {}) {
  const targetUser = store.getUserById(targetUserId);
  if (!targetUser) throw new Error('ما لقينا هذه القناة بقاعدة البيانات');

  let senderUser;

  if (asBot) {
    const botId = store.getBotAccountId();
    if (!botId) {
      throw new Error('ما حددت بعد حساب بوت الموقع. من لوحة التحكم اختر أي حساب مرتبط واجعله "بوت الموقع" أول.');
    }
    senderUser = store.getUserById(botId);
    if (!senderUser) {
      throw new Error('حساب البوت المحدد ما عاد موجود بقاعدة البيانات — حدد حساب ثاني كبوت الموقع.');
    }
    if (!senderUser.access_token || !senderUser.refresh_token) {
      throw new Error('حساب البوت ما عنده access_token أو refresh_token محفوظ — لازم يعيد تسجيل الدخول (OAuth) من جديد.');
    }
  } else {
    senderUser = targetUser;
  }

  senderUser = await refreshIfNeeded(senderUser);

  const payload = {
    type: asBot ? 'bot' : 'user',
    content: message,
    broadcaster_user_id: Number(targetUser.user_id)
  };

  const res = await fetch('https://api.kick.com/public/v1/chat', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${senderUser.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    // تسجيل كامل للتشخيص — يطبع الطلب والرد بالضبط
    console.error('[Kick] فشل إرسال الرسالة');
    console.error('[Kick] Status:', res.status);
    console.error('[Kick] Payload المُرسَل:', JSON.stringify(payload));
    console.error('[Kick] رد Kick:', JSON.stringify(data));

    // رسائل مخصصة لأشهر الحالات المعروفة
    if (res.status === 401) {
      throw new Error('فشل الإرسال: التوكن غير صالح أو منتهي (401). تأكد إن حساب البوت سجل دخول صحيح.');
    }
    if (res.status === 403) {
      throw new Error('فشل الإرسال: صلاحيات ناقصة (403). تأكد إن حساب البوت عنده scope: chat:write، وإنه غير محظور بالقناة، وإن التطبيق مفعّل كبوت من لوحة Kick.');
    }
    if (res.status === 422 || res.status === 400) {
      throw new Error('فشل الإرسال: بيانات الطلب مرفوضة (' + res.status + '). التفاصيل: ' + (data?.message || JSON.stringify(data)));
    }

    throw new Error(data?.message || `فشل إرسال الرسالة (status ${res.status})`);
  }

  return data;
}

// حظر أو تايم آوت مستخدم من شات المستخدم (broadcaster) اللي عطاك الصلاحية
// duration بالدقائق (1 لين 10080 = 7 أيام) — لو ما حطيته يكون حظر دائم
async function banUser(broadcasterUserId, targetUserId, reason, durationMinutes) {
  let user = store.getUserById(broadcasterUserId);
  if (!user) throw new Error('ما لقينا هذا البثّاث بقاعدة البيانات');

  user = await refreshIfNeeded(user);

  const body = {
    broadcaster_user_id: Number(broadcasterUserId),
    user_id: Number(targetUserId)
  };
  if (reason) body.reason = String(reason).slice(0, 255);
  if (durationMinutes) body.duration = Number(durationMinutes);

  const res = await fetch('https://api.kick.com/public/v1/moderation/bans', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${user.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    console.error('[Kick] فشل الحظر — status:', res.status, 'response:', JSON.stringify(data));
    throw new Error(data?.message || `فشل الحظر (status ${res.status})`);
  }
  return data;
}

// فك الحظر / التايم آوت
async function unbanUser(broadcasterUserId, targetUserId) {
  let user = store.getUserById(broadcasterUserId);
  if (!user) throw new Error('ما لقينا هذا البثّاث بقاعدة البيانات');

  user = await refreshIfNeeded(user);

  const res = await fetch('https://api.kick.com/public/v1/moderation/bans', {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${user.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      broadcaster_user_id: Number(broadcasterUserId),
      user_id: Number(targetUserId)
    })
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    console.error('[Kick] فشل فك الحظر — status:', res.status, 'response:', JSON.stringify(data));
    throw new Error(data?.message || `فشل فك الحظر (status ${res.status})`);
  }
  return data;
}

// تعديل بيانات القناة (عنوان البث + الكاتيجوري) — يعدّل قناة صاحب التوكن نفسه
async function updateChannel(broadcasterUserId, { streamTitle, categoryId }) {
  let user = store.getUserById(broadcasterUserId);
  if (!user) throw new Error('ما لقينا هذا البثّاث بقاعدة البيانات');

  user = await refreshIfNeeded(user);

  const body = {};
  if (streamTitle !== undefined && streamTitle !== '') body.stream_title = streamTitle;
  if (categoryId !== undefined && categoryId !== '') body.category_id = Number(categoryId);

  if (Object.keys(body).length === 0) {
    throw new Error('ما فيه شي تعدّله (لازم عنوان بث أو كاتيجوري)');
  }

  const res = await fetch('https://api.kick.com/public/v1/channels', {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${user.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    console.error('[Kick] فشل تعديل القناة — status:', res.status, 'response:', JSON.stringify(data));
    throw new Error(data?.message || `فشل تعديل القناة (status ${res.status})`);
  }
  return data;
}

module.exports = { sendChatMessage, banUser, unbanUser, updateChannel };
