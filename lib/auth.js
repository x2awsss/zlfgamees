const crypto = require('crypto');

// ===== تشفير كلمة سر الأدمن =====
// نستخدم scrypt المدمجة في Node.js (مو بحاجة لمكتبة خارجية مثل bcrypt)
// الناتج بصيغة "salt:hash" ونخزنه بمتغير البيئة ADMIN_PASSWORD_HASH

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string' || !storedHash.includes(':')) {
    return false;
  }
  const [salt, hash] = storedHash.split(':');
  try {
    const hashBuffer = Buffer.from(hash, 'hex');
    const suppliedHashBuffer = crypto.scryptSync(password, salt, 64);
    // نستخدم timingSafeEqual عشان نمنع هجمات قياس الوقت (timing attacks)
    return (
      hashBuffer.length === suppliedHashBuffer.length &&
      crypto.timingSafeEqual(hashBuffer, suppliedHashBuffer)
    );
  } catch (err) {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };
