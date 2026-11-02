// สร้าง/อัปเดตตารางใน Supabase: DATABASE_URL=... node scripts/migrate.js  (หรือวาง db/schema.sql ใน SQL Editor ของ Supabase)
const { open } = require("../src/db");
if (!process.env.DATABASE_URL) { console.error("ต้องตั้ง DATABASE_URL"); process.exit(1); }
open({ url: process.env.DATABASE_URL }).then(db => db.close()).then(() => console.log("สร้างตารางเรียบร้อย")).catch(e => { console.error(e.message); process.exit(1); });
