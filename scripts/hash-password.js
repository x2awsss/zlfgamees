// استخدام: node scripts/hash-password.js "كلمة-السر-اللي-تبيها"
// راح يطبع لك سطر جاهز تحطه بملف .env

const { hashPassword } = require('../lib/auth');

const password = process.argv[2];

if (!password) {
  console.error('لازم تعطي كلمة السر كوسيط: node scripts/hash-password.js "مثال123"');
  process.exit(1);
}

const hash = hashPassword(password);
console.log('\nضيف هذا السطر بملف .env عندك:\n');
console.log(`ADMIN_PASSWORD_HASH=${hash}\n`);
