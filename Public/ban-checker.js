setInterval(async () => {
  try {
    const res = await fetch('/api/check-ban-status');
    const data = await res.json();
    if (data.banned) {
      window.location.reload();
    }
  } catch (e) {}
}, 2000);
