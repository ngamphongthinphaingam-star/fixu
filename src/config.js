// สร้างค่าตั้งค่าจาก environment และตรวจความพร้อมก่อนใช้งานจริง (ใช้ร่วมกันทั้งเซิร์ฟเวอร์ปกติและ Vercel)
function buildConfig(e) {
  const prod = e.NODE_ENV === "production", mode = e.AUTH_MODE || "dev";
  const cfg = {
    authMode: mode, devLogin: mode === "dev" && !prod,
    secret: e.SESSION_SECRET || "dev-only-secret-change-me",
    secureCookie: e.COOKIE_SECURE ? e.COOKIE_SECURE === "1" : prod, trustProxy: e.TRUST_PROXY === "1" || !!e.VERCEL,
    allowedDomain: e.ALLOWED_EMAIL_DOMAIN || "",
    adminEmails: (e.ADMIN_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean),
    pilotCode: e.PILOT_CODE || "",
    geminiApiKey: e.GEMINI_API_KEY || "", geminiModel: e.GEMINI_MODEL || "gemini-3.1-flash-lite",
    proxySecret: e.PROXY_SECRET || "", proxyEmailHeader: e.PROXY_EMAIL_HEADER, proxyNameHeader: e.PROXY_NAME_HEADER,
    reopenDays: Number(e.REOPEN_DAYS || 7),
  };
  if (prod) {
    const bad = [];
    if (!["proxy", "local"].includes(mode)) bad.push("ต้องตั้ง AUTH_MODE=local (ช่วงทดสอบ) หรือ proxy (SSO มหาวิทยาลัย)");
    if (mode === "proxy") {
      if (cfg.proxySecret.length < 24) bad.push("PROXY_SECRET ต้องยาวอย่างน้อย 24 ตัวอักษร");
      if (!cfg.allowedDomain) bad.push("ต้องตั้ง ALLOWED_EMAIL_DOMAIN");
    }
    if (mode === "local") {
      if (cfg.pilotCode.length < 8) bad.push("PILOT_CODE (รหัสเข้าร่วมทดสอบ) ต้องยาวอย่างน้อย 8 ตัวอักษร");
      if (cfg.secret.length < 32 || cfg.secret.startsWith("dev-only")) bad.push("SESSION_SECRET ต้องเป็นสตริงสุ่มยาวอย่างน้อย 32 ตัวอักษร");
    }
    if (!e.DATABASE_URL) bad.push("ต้องตั้ง DATABASE_URL (สตริงเชื่อมต่อ Supabase/PostgreSQL) เมื่อใช้งานจริง");
    if (!cfg.adminEmails.length) bad.push("ต้องตั้ง ADMIN_EMAILS อย่างน้อย 1 อีเมล");
    if (bad.length) throw new Error("ตั้งค่าไม่ครบ:\n- " + bad.join("\n- "));
  }
  return cfg;
}
module.exports = { buildConfig };
