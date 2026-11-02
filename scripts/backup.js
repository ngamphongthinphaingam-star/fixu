// ส่งออกข้อมูลทั้งหมดเป็นไฟล์ JSON (รวมรูปแบบ base64): node scripts/backup.js [โฟลเดอร์]
// หมายเหตุ: Supabase มีระบบสำรองของตัวเอง (ขึ้นกับแพ็กเกจ) — ไฟล์นี้เป็นสำเนาที่คุณถือเองเพิ่มอีกชั้น
const { open } = require("../src/db"); const fs = require("fs");
(async () => {
  const db = await open({ url: process.env.DATABASE_URL, dir: process.env.DATABASE_URL ? undefined : (process.env.PGLITE_DIR || "./data/pg") });
  const out = {}; for (const t of ["users", "tickets", "ticket_images", "ticket_history", "notifications", "audit_logs"]) {
    out[t] = (await db.q(`SELECT * FROM ${t}`)).map(r => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, Buffer.isBuffer(v) ? v.toString("base64") : v]))); }
  const dir = process.argv[2] || "./backups"; fs.mkdirSync(dir, { recursive: true });
  const f = `${dir}/fixu-${new Date().toISOString().replace(/[:.]/g, "-")}.json`; fs.writeFileSync(f, JSON.stringify(out)); console.log("สำรองแล้ว:", f); await db.close();
})();
