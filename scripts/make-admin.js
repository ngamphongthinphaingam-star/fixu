// node scripts/make-admin.js อีเมล  (ผู้ใช้ต้องเข้าสู่ระบบอย่างน้อย 1 ครั้ง หรือใส่ใน ADMIN_EMAILS)
const { open } = require("../src/db");
(async () => {
  const db = await open({ url: process.env.DATABASE_URL, dir: process.env.DATABASE_URL ? undefined : (process.env.PGLITE_DIR || "./data/pg") });
  const r = await db.q("UPDATE users SET role='admin' WHERE email=$1 RETURNING id", [(process.argv[2] || "").toLowerCase()]);
  console.log(r.length ? "ตั้งเป็นผู้ดูแลระบบแล้ว" : "ไม่พบผู้ใช้"); await db.close();
})();
