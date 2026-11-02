// จุดเข้าสำหรับ Vercel (serverless): สร้างแอปครั้งเดียวต่ออินสแตนซ์ แล้วส่งคำขอให้ Express
const { buildConfig } = require("./config"), { open } = require("./db"), { createApp } = require("./app"), { makeNotifier } = require("./notify");
let appP = null;
async function init() {
  const e = process.env, cfg = buildConfig(e);
  cfg.db = await open({ url: e.DATABASE_URL, migrate: false }); // ตารางสร้างล่วงหน้าด้วย db/schema.sql หรือ npm run migrate
  cfg.notify = makeNotifier({ smtpUrl: e.SMTP_URL, mailFrom: e.MAIL_FROM || "FixU <no-reply@example.ac.th>" });
  return createApp(cfg);
}
module.exports = async (req, res) => {
  try { appP ||= init(); return (await appP)(req, res); }
  catch (err) {
    appP = null; console.error("[handler] เริ่มระบบไม่สำเร็จ:", err.message);
    res.statusCode = 500; res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ error: "ระบบยังตั้งค่าไม่ครบหรือเชื่อมฐานข้อมูลไม่ได้" }));
  }
};
