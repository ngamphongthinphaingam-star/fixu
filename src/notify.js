// ส่งอีเมลแจ้งเตือน: ถ้าไม่ตั้ง SMTP_URL จะแค่บันทึกลง log (ไม่ส่งจริง)
function makeNotifier(cfg) {
  let tr = null;
  if (cfg.smtpUrl) tr = require("nodemailer").createTransport(cfg.smtpUrl);
  return async (email, subject, text) => {
    if (!tr) { if (!cfg.quiet) console.log("[notify:log]", email, subject); return; }
    try { await tr.sendMail({ from: cfg.mailFrom, to: email, subject, text }); }
    catch (e) { console.error("[notify] ส่งอีเมลไม่สำเร็จ:", e.message); }
  };
}
module.exports = { makeNotifier };
