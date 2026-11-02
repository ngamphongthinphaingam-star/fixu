// ลบ Ticket ที่เก่ากว่า RETENTION_DAYS (ค่าเริ่มต้น 365) พร้อมรูปและประวัติ — ตั้ง cron รันเป็นระยะ
const { open } = require("../src/db");
(async () => {
  const db = await open({ url: process.env.DATABASE_URL, dir: process.env.DATABASE_URL ? undefined : (process.env.PGLITE_DIR || "./data/pg") });
  const days = Number(process.env.RETENTION_DAYS || 365), cut = Date.now() - days * 86400000;
  const r = await db.q("DELETE FROM tickets WHERE created_at<$1 RETURNING id", [cut]);
  await db.q("DELETE FROM notifications WHERE created_at<$1", [cut]);
  await db.q("INSERT INTO audit_logs(action,detail,created_at) VALUES('retention.purge',$1,$2)", [`ลบ ${r.length} Ticket เก่ากว่า ${days} วัน`, Date.now()]);
  console.log("ลบ Ticket:", r.length); await db.close();
})();
