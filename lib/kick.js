const fetch = require('node-fetch');
const store = require('./store');

// يجدد التوكن تلقائياً لو باقي أقل من دقيقة على انتهائه
async function refreshIfNeeded(user) {
  const bufferMs = 60 * 1000;
  if (Date.now() < user.expires_at - bufferMs) return user;

  const res = await fetch('https://id.kick.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      refresh_token: user.refresh_token
    })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error('فشل تجديد التوكن — المستخدم غالباً سحب الصلاحية من حسابه بـ Kick: ' + JSON.stringify(data));
  }

  return store.updateTokens(user.user_id, data);
}

// يرسل رسالة داخل شات قناة "targetUserId" — إما باسم صاحب القناة نفسه، أو باسم حساب بوت الموقع
// (حساب البوت لازم يكون سجل دخول عندك مرة قبل وتحدد كـ"بوت الموقع" من لوحة التحكم)
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
  } else {
    senderUser = targetUser;
  }

  senderUser = await refreshIfNeeded(senderUser);

  const res = await fetch('https://api.kick.com/public/v1/chat', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${senderUser.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      type: 'user',
      content: message,
      broadcaster_user_id: Number(targetUser.user_id)
    })
  });

  const data = await res.json();
  if (!res.ok) {
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
    throw new Error(data?.message || `فشل تعديل القناة (status ${res.status})`);
  }
  return data;
}

module.exports = { sendChatMessage, banUser, unbanUser, updateChannel };