// فحص فوري كل ثانيتين لطرد المستخدم المحظور فوراً
setInterval(async () => {
  try {
    const res = await fetch('/api/check-ban-status');
    const data = await res.json();
    if (data.banned) {
      window.location.reload(); // إعادة تحميل الصفحة ليظهر كود الحظر الأحمر فوراً
    }
  } catch (e) {
    // تجاهل الأخطاء العابرة في الشبكة
  }
}, 2000);
