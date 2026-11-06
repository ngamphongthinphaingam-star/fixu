const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { PgStore } = require("./ratestore");
const path = require("path");
const { analyzeIncident, redactPrivateText } = require("./gemini");

const ST = ["รอตรวจสอบ", "รับเรื่องแล้ว", "กำลังดำเนินการ", "แก้ไขแล้ว"];
const BUILDINGS = ["A", "B", "C", "D"];
const KNOWN_TYPES = ["ไฟฟ้า", "แอร์", "น้ำรั่ว", "ห้องน้ำ", "โต๊ะเก้าอี้"];
const clean = (s, max, multi) =>
  String(s ?? "").replace(multi ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g : /[\u0000-\u001f\u007f]/g, "").trim().slice(0, max);
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

function createApp(cfg) {
  const db = cfg.db, notify = cfg.notify || (async () => {});
  const app = express();
  app.disable("x-powered-by");
  if (cfg.trustProxy) app.set("trust proxy", 1);
  app.use(helmet({ contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], objectSrc: ["'none'"],
    frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"] } } }));
  app.use(express.json({ limit: "4mb" }));
  app.use(cookieParser());
  app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: cfg.apiLimit || 600, standardHeaders: true, legacyHeaders: false }));
  // ป้องกัน CSRF: คำขอที่เปลี่ยนข้อมูลต้องมี header พิเศษ (เว็บอื่นส่งข้ามไซต์ไม่ได้ถ้าไม่มี CORS)
  app.use("/api", (req, res, next) => {
    if (!["GET", "HEAD", "OPTIONS"].includes(req.method) && req.get("x-requested-with") !== "fixu")
      return res.status(403).json({ error: "คำขอไม่ถูกต้อง" });
    next();
  });

  const audit = (u, action, target, detail, req, t = db) => t.q(
    "INSERT INTO audit_logs(actor_id,actor_email,action,target,detail,ip,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
    [u?.id ?? null, u?.email ?? null, action, target ?? null, detail ?? null, req?.ip ?? null, Date.now()]);

  async function upsert(email, name) {
    email = String(email || "").toLowerCase().trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 120) return null;
    if (cfg.allowedDomain && !email.endsWith("@" + cfg.allowedDomain)) return null;
    const isAdm = (cfg.adminEmails || []).includes(email);
    await db.q("INSERT INTO users(id,email,name,role,active,created_at) VALUES($1,$2,$3,$4,TRUE,$5) ON CONFLICT(email) DO NOTHING",
      [crypto.randomUUID(), email, clean(name, 80) || email, isAdm ? "admin" : "user", Date.now()]);
    if (isAdm) await db.q("UPDATE users SET role='admin' WHERE email=$1", [email]);
    const u = (await db.q("SELECT * FROM users WHERE email=$1", [email]))[0];
    return u && u.active ? u : null;
  }
  async function auth(req, res, next) {
    let u = null;
    if (cfg.authMode === "proxy") {
      // เชื่อ header เฉพาะเมื่อมี secret ที่ตรงกับ reverse proxy ของมหาวิทยาลัย
      if (cfg.proxySecret && req.get("x-proxy-secret") && eq(req.get("x-proxy-secret"), cfg.proxySecret)) {
        const em = req.get(cfg.proxyEmailHeader || "x-forwarded-email");
        if (em) u = await upsert(em, req.get(cfg.proxyNameHeader || "x-forwarded-user") || "");
      }
    } else if (req.cookies.fixu) {
      try {
        const p = jwt.verify(req.cookies.fixu, cfg.secret, { algorithms: ["HS256"] });
        u = (await db.q("SELECT * FROM users WHERE id=$1 AND active=TRUE", [p.sub]))[0];
      } catch { /* โทเคนไม่ถูกต้อง */ }
    }
    if (!u) return res.status(401).json({ error: "ต้องเข้าสู่ระบบ" });
    req.user = u; next();
  }
  const need = (...roles) => (req, res, next) =>
    roles.includes(req.user.role) ? next() : res.status(403).json({ error: "ไม่มีสิทธิ์ดำเนินการ" });

  app.get("/healthz", async (req, res) => { try { await db.q("SELECT 1"); res.json({ ok: true }); } catch { res.status(503).json({ ok: false }); } });
  app.get("/api/config", (req, res) => res.json({ authMode: cfg.authMode, devLogin: !!cfg.devLogin, localLogin: cfg.authMode === "local" }));
  const issue = async (req, res, u, detail) => {
    const tok = jwt.sign({ sub: u.id }, cfg.secret, { algorithm: "HS256", expiresIn: "8h" });
    res.cookie("fixu", tok, { httpOnly: true, sameSite: "lax", secure: !!cfg.secureCookie, maxAge: 8 * 3600 * 1000 });
    await audit(u, "login", u.email, detail, req); res.json({ ok: true });
  };
  app.post("/api/dev-login", async (req, res) => {
    if (!cfg.devLogin) return res.status(404).json({ error: "ไม่พบ" });
    const u = await upsert(req.body?.email, req.body?.name);
    if (!u) return res.status(403).json({ error: "อีเมลนี้ไม่ได้รับอนุญาต" });
    await issue(req, res, u, null);
  });
  // โหมดทดสอบ (pilot): เข้าด้วยอีเมล + รหัสเข้าร่วมที่ผู้ดูแลแจก ไม่ต้องเชื่อมบัญชีมหาวิทยาลัย
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: cfg.loginLimit || 10, standardHeaders: true, legacyHeaders: false, store: new PgStore(db, "login:"),
    message: { error: "ลองเข้าสู่ระบบบ่อยเกินไป กรุณารอสักครู่" } });
  app.post("/api/local-login", loginLimiter, async (req, res) => {
    if (cfg.authMode !== "local" || !cfg.pilotCode) return res.status(404).json({ error: "ไม่พบ" });
    if (!eq(String(req.body?.code || ""), cfg.pilotCode)) return res.status(403).json({ error: "รหัสเข้าร่วมไม่ถูกต้อง" });
    const u = await upsert(req.body?.email, req.body?.name);
    if (!u) return res.status(403).json({ error: "อีเมลนี้ไม่ได้รับอนุญาต" });
    await issue(req, res, u, "pilot");
  });
  app.post("/api/logout", (req, res) => { res.clearCookie("fixu"); res.json({ ok: true }); });
  app.get("/api/me", auth, (req, res) => { const { id, email, name, role } = req.user; res.json({ id, email, name, role }); });

  // ---------- Ticket ----------
  const serMany = async rows => {
    if (!rows.length) return [];
    const ids = rows.map(r => r.id);
    const imgs = await db.q("SELECT id,ticket_id FROM ticket_images WHERE ticket_id = ANY($1::text[]) ORDER BY created_at", [ids]);
    const his = await db.q("SELECT * FROM ticket_history WHERE ticket_id = ANY($1::text[]) AND kind<>'create' ORDER BY id", [ids]);
    const gi = {}, gh = {};
    imgs.forEach(i => (gi[i.ticket_id] ||= []).push("/api/images/" + i.id));
    his.forEach(h => (gh[h.ticket_id] ||= []).push({ s: h.status, ts: h.created_at, w: h.actor_name, n: h.note }));
    return rows.map(t => ({ id: t.id, t: t.type, b: t.building, r: t.room, d: t.description, o: t.owner_id, ts: t.created_at,
      im: gi[t.id] || [], ops: { s: t.status, t: t.updated_at, a: t.assignee, h: gh[t.id] || [] } }));
  };
  const addHist = (t, ticketId, kind, status, u, note) => t.q(
    "INSERT INTO ticket_history(ticket_id,kind,status,actor_id,actor_name,note,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
    [ticketId, kind, status, u.id, u.name, note || null, Date.now()]);
  const tell = async (ownerId, ticketId, msg) => {
    await db.q("INSERT INTO notifications(user_id,ticket_id,message,created_at) VALUES($1,$2,$3,$4)", [ownerId, ticketId, msg, Date.now()]);
    const o = (await db.q("SELECT email FROM users WHERE id=$1", [ownerId]))[0];
    if (o) await notify(o.email, "FixU: " + ticketId, msg).catch(() => {}); // รอให้ส่งเสร็จ เพราะ serverless อาจหยุดทำงานทันทีหลังตอบกลับ
  };
  const decode = uri => {
    const m = /^data:image\/(jpeg|png);base64,([A-Za-z0-9+/=]+)$/.exec(String(uri));
    if (!m) return null;
    const buf = Buffer.from(m[2], "base64");
    if (buf.length === 0 || buf.length > 700 * 1024) return null;
    const jpg = buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
    const png = buf.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    if ((m[1] === "jpeg" && !jpg) || (m[1] === "png" && !png)) return null;
    return { mime: "image/" + m[1], buf };
  };
  const createLimiter = rateLimit({ windowMs: 3600 * 1000, limit: cfg.createLimit || 20, keyGenerator: r => r.user.id, store: new PgStore(db, "create:"),
    validate: false, message: { error: "แจ้งปัญหาบ่อยเกินไป กรุณารอสักครู่" } });

  const aiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, keyGenerator: r => r.user.id,
    store: new PgStore(db, "ai:"), validate: false,
    message: { error: "ใช้ผู้ช่วย AI บ่อยเกินไป กรุณารอ 15 นาทีแล้วลองใหม่" } });
  app.post("/api/ai/analyze", auth, aiLimiter, async (req, res) => {
    if (!cfg.geminiApiKey) return res.status(503).json({ error: "ยังไม่ได้ตั้งค่า Gemini API Key" });
    const description = clean(req.body?.description, 500, true);
    const type = clean(req.body?.type, 40);
    if (description.length < 8) return res.status(400).json({ error: "กรุณาใส่รายละเอียดอย่างน้อย 8 ตัวอักษร" });
    try {
      const result = await analyzeIncident({
        apiKey: cfg.geminiApiKey,
        model: cfg.geminiModel,
        type,
        description: redactPrivateText(description),
      });
      res.json({ analysis: result });
    } catch (err) {
      const status = err.name === "TimeoutError" || err.name === "AbortError" ? 504 : (err.status === 429 ? 429 : 502);
      const message = status === 429
        ? "โควตา Gemini ชั่วคราวเต็ม กรุณาลองใหม่ภายหลัง"
        : status === 504
          ? "AI ใช้เวลานานเกินไป กรุณาลองใหม่"
          : err.status === 401 || err.status === 403
            ? "Gemini ปฏิเสธ API Key หรือโปรเจกต์นี้ยังไม่มีสิทธิ์ใช้โมเดล กรุณาตรวจ GEMINI_API_KEY และสถานะ Free tier ใน AI Studio"
            : err.status === 400
              ? "คำขอ Gemini ไม่ถูกต้อง กรุณาตรวจชื่อโมเดลและรูปแบบ API แล้วลองใหม่"
              : "วิเคราะห์ไม่สำเร็จในขณะนี้ ลองอีกครั้งหรือส่งเรื่องโดยไม่ใช้ AI";
      res.status(status).json({ error: message });
    }
  });

  app.get("/api/tickets", auth, async (req, res) => {
    const rows = req.user.role === "user"
      ? await db.q("SELECT * FROM tickets WHERE owner_id=$1 ORDER BY created_at DESC LIMIT 500", [req.user.id])
      : await db.q("SELECT * FROM tickets ORDER BY created_at DESC LIMIT 500");
    res.json({ tickets: await serMany(rows) });
  });
  app.post("/api/tickets", auth, createLimiter, async (req, res) => {
    const b = req.body || {};
    const type = clean(b.type, 40), room = clean(b.room, 40), desc = clean(b.description, 500, true);
    if (!type || !room || !desc) return res.status(400).json({ error: "กรุณากรอกประเภท ห้อง และรายละเอียดให้ครบ" });
    if (!BUILDINGS.includes(b.building)) return res.status(400).json({ error: "อาคารไม่ถูกต้อง" });
    const imgs = Array.isArray(b.images) ? b.images : [];
    if (imgs.length > 3) return res.status(400).json({ error: "แนบรูปได้สูงสุด 3 รูป" });
    const dec = imgs.map(decode);
    if (dec.some(x => !x)) return res.status(400).json({ error: "ไฟล์รูปไม่ถูกต้อง (รองรับ JPG/PNG ไม่เกิน 700 KB หลังย่อ)" });
    const id = "FX-" + Date.now().toString(36).slice(-5).toUpperCase() + crypto.randomBytes(1).toString("hex").toUpperCase();
    const now = Date.now();
    await db.tx(async t => {
      await t.q("INSERT INTO tickets(id,owner_id,type,building,room,description,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)",
        [id, req.user.id, type, b.building, room, desc, now]);
      for (const d of dec) await t.q("INSERT INTO ticket_images(id,ticket_id,mime,data,created_at) VALUES($1,$2,$3,$4,$5)",
        [crypto.randomUUID(), id, d.mime, d.buf, now]);
      await addHist(t, id, "create", 0, req.user, null);
      await audit(req.user, "ticket.create", id, null, req, t);
    });
    await tell(req.user.id, id, `ระบบรับเรื่อง ${id} แล้ว รอเจ้าหน้าที่ตรวจสอบ`);
    res.status(201).json({ id });
  });
  const getT = async id => (await db.q("SELECT * FROM tickets WHERE id=$1", [String(id)]))[0];
  app.post("/api/tickets/:id/status", auth, need("staff", "admin"), async (req, res) => {
    const t = await getT(req.params.id); if (!t) return res.status(404).json({ error: "ไม่พบ Ticket" });
    const to = Number(req.body?.status);
    if (!Number.isInteger(to) || to !== t.status + 1 || to > 3) return res.status(400).json({ error: "ลำดับสถานะไม่ถูกต้อง" });
    const a = Number(req.body?.assignee ?? t.assignee);
    if (!Number.isInteger(a) || a <= 0) return res.status(400).json({ error: "กรุณาเลือกผู้รับผิดชอบก่อนเปลี่ยนสถานะ" });
    if (a !== Number(t.assignee) && !(await db.q("SELECT id FROM responsibility_categories WHERE id=$1 AND active=TRUE", [a])).length)
      return res.status(400).json({ error: "หน่วยงานผู้รับผิดชอบไม่ถูกต้องหรือปิดใช้งานแล้ว" });
    const note = clean(req.body?.note, 200, true);
    if (to === 3 && !note) return res.status(400).json({ error: "ต้องบันทึกผลการแก้ไขก่อนปิดงาน" });
    const now = Date.now();
    const ok = await db.tx(async tx => {
      // เช็กสถานะเดิมในคำสั่งเดียว กันสองคนกดพร้อมกัน
      const r = await tx.q("UPDATE tickets SET status=$1,assignee=$2,updated_at=$3,closed_at=$4::bigint,resolution=COALESCE($5::text,resolution) WHERE id=$6 AND status=$7 RETURNING id",
        [to, a, now, to === 3 ? now : null, to === 3 ? note : null, t.id, t.status]);
      if (!r.length) return false;
      await addHist(tx, t.id, "status", to, req.user, note);
      await audit(req.user, "ticket.status", t.id, `${ST[t.status]} -> ${ST[to]}`, req, tx);
      return true;
    });
    if (!ok) return res.status(409).json({ error: "Ticket ถูกเปลี่ยนสถานะโดยผู้อื่นแล้ว กรุณารีเฟรช" });
    await tell(t.owner_id, t.id, `${t.id} เปลี่ยนสถานะเป็น “${ST[to]}”` + (to === 3 ? ` (${note})` : ""));
    res.json({ ok: true });
  });
  app.post("/api/tickets/:id/request-info", auth, need("staff", "admin"), async (req, res) => {
    const t = await getT(req.params.id); if (!t) return res.status(404).json({ error: "ไม่พบ Ticket" });
    if (t.status >= 3) return res.status(400).json({ error: "Ticket ปิดแล้ว" });
    const note = clean(req.body?.note, 200, true) || "ขอข้อมูลเพิ่มจากผู้แจ้ง";
    await addHist(db, t.id, "info", t.status, req.user, note); await audit(req.user, "ticket.info", t.id, note, req);
    await tell(t.owner_id, t.id, `${t.id}: เจ้าหน้าที่ขอข้อมูลเพิ่ม — ${note}`);
    res.json({ ok: true });
  });
  app.post("/api/tickets/:id/reopen", auth, async (req, res) => {
    const t = await getT(req.params.id);
    if (!t || t.owner_id !== req.user.id) return res.status(404).json({ error: "ไม่พบ Ticket" });
    if (t.status !== 3) return res.status(400).json({ error: "เปิดซ้ำได้เฉพาะ Ticket ที่ปิดแล้ว" });
    if (Date.now() - t.closed_at > (cfg.reopenDays || 7) * 86400000) return res.status(400).json({ error: "พ้นกำหนดเปิดซ้ำแล้ว กรุณาแจ้งเรื่องใหม่" });
    await db.tx(async tx => {
      await tx.q("UPDATE tickets SET status=0,assignee=0,updated_at=$1,closed_at=NULL,reopen_count=reopen_count+1 WHERE id=$2", [Date.now(), t.id]);
      await addHist(tx, t.id, "reopen", 0, req.user, "เปิดเรื่องซ้ำ"); await audit(req.user, "ticket.reopen", t.id, null, req, tx);
    });
    res.json({ ok: true });
  });
  app.get("/api/images/:id", auth, async (req, res) => {
    const i = (await db.q("SELECT i.mime,i.data,t.owner_id FROM ticket_images i JOIN tickets t ON t.id=i.ticket_id WHERE i.id=$1", [String(req.params.id)]))[0];
    if (!i || (req.user.role === "user" && i.owner_id !== req.user.id)) return res.status(404).end();
    res.set("Content-Type", i.mime).set("Cache-Control", "private, max-age=3600").send(i.data);
  });
  app.get("/api/notifications", auth, async (req, res) =>
    res.json({ items: await db.q("SELECT id,ticket_id,message,created_at,is_read AS read FROM notifications WHERE user_id=$1 ORDER BY id DESC LIMIT 100", [req.user.id]) }));
  app.get("/api/stats", auth, async (req, res) => {
    const c = { p: 0, g: 0, d: 0 };
    (await db.q("SELECT status,COUNT(*)::int n FROM tickets GROUP BY status")).forEach(r => { if (r.status === 0) c.p += r.n; else if (r.status === 3) c.d += r.n; else c.g += r.n; });
    c.a = c.p + c.g + c.d;
    const types = Object.fromEntries([...KNOWN_TYPES, "อื่น ๆ"].map(k => [k, 0]));
    (await db.q("SELECT type,COUNT(*)::int n FROM tickets GROUP BY type")).forEach(r => { types[KNOWN_TYPES.includes(r.type) ? r.type : "อื่น ๆ"] += r.n; });
    res.json({ counts: c, types });
  });

  // ---------- ผู้ดูแลระบบ ----------
  app.get("/api/settings", auth, async (req, res) => {
    const [departments, rooms] = await Promise.all([
      db.q("SELECT id,name,active FROM responsibility_categories ORDER BY id"),
      db.q("SELECT building,room,active FROM room_catalog ORDER BY building,room"),
    ]);
    res.json({ departments, rooms });
  });
  app.post("/api/admin/departments", auth, need("admin"), async (req, res) => {
    const name = clean(req.body?.name, 60);
    if (!name) return res.status(400).json({ error: "กรุณาระบุชื่อหน่วยงาน" });
    if ((await db.q("SELECT id FROM responsibility_categories WHERE lower(name)=lower($1)", [name])).length)
      return res.status(409).json({ error: "มีชื่อหน่วยงานนี้แล้ว" });
    const row = (await db.q("INSERT INTO responsibility_categories(name,active,created_at) VALUES($1,TRUE,$2) RETURNING id,name,active", [name, Date.now()]))[0];
    await audit(req.user, "settings.department.create", row.id, row.name, req);
    res.status(201).json({ department: row });
  });
  app.put("/api/admin/departments/:id", auth, need("admin"), async (req, res) => {
    const id = Number(req.params.id), name = clean(req.body?.name, 60), active = req.body?.active !== false;
    if (!Number.isInteger(id) || id < 1 || !name) return res.status(400).json({ error: "ข้อมูลหน่วยงานไม่ถูกต้อง" });
    if (!active) {
      const current = (await db.q("SELECT active FROM responsibility_categories WHERE id=$1", [id]))[0];
      if (current?.active && Number((await db.q("SELECT COUNT(*)::int AS n FROM responsibility_categories WHERE active=TRUE"))[0]?.n || 0) <= 1)
        return res.status(400).json({ error: "ต้องเหลือหน่วยงานที่ใช้งานอย่างน้อย 1 รายการ" });
    }
    if ((await db.q("SELECT id FROM responsibility_categories WHERE lower(name)=lower($1) AND id<>$2", [name, id])).length)
      return res.status(409).json({ error: "มีชื่อหน่วยงานนี้แล้ว" });
    const row = (await db.q("UPDATE responsibility_categories SET name=$1,active=$2 WHERE id=$3 RETURNING id,name,active", [name, active, id]))[0];
    if (!row) return res.status(404).json({ error: "ไม่พบหน่วยงาน" });
    await audit(req.user, "settings.department.update", id, `${row.name} (${active ? "active" : "inactive"})`, req);
    res.json({ department: row });
  });
  app.delete("/api/admin/departments/:id", auth, need("admin"), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: "รหัสหน่วยงานไม่ถูกต้อง" });
    const current = (await db.q("SELECT active FROM responsibility_categories WHERE id=$1", [id]))[0];
    if (!current) return res.status(404).json({ error: "ไม่พบหน่วยงาน" });
    if (current.active && Number((await db.q("SELECT COUNT(*)::int AS n FROM responsibility_categories WHERE active=TRUE"))[0]?.n || 0) <= 1)
      return res.status(400).json({ error: "ต้องเหลือหน่วยงานที่ใช้งานอย่างน้อย 1 รายการ" });
    const row = (await db.q("UPDATE responsibility_categories SET active=FALSE WHERE id=$1 RETURNING id,name", [id]))[0];
    if (!row) return res.status(404).json({ error: "ไม่พบหน่วยงาน" });
    await audit(req.user, "settings.department.deactivate", id, row.name, req);
    res.json({ ok: true });
  });
  app.post("/api/admin/rooms", auth, need("admin"), async (req, res) => {
    const building = clean(req.body?.building, 1), room = clean(req.body?.room, 40);
    if (!BUILDINGS.includes(building) || !room) return res.status(400).json({ error: "กรุณาเลือกอาคารและระบุเลขห้อง" });
    const existing = (await db.q("SELECT room,active FROM room_catalog WHERE building=$1 AND lower(room)=lower($2)", [building, room]))[0];
    if (existing?.active) return res.status(409).json({ error: "มีเลขห้องนี้ในอาคารแล้ว" });
    if (existing) {
      await db.q("UPDATE room_catalog SET active=TRUE WHERE building=$1 AND room=$2", [building, existing.room]);
      await audit(req.user, "settings.room.restore", `${building}/${existing.room}`, null, req);
      return res.json({ ok: true, restored: true });
    }
    await db.q("INSERT INTO room_catalog(building,room,active,created_at) VALUES($1,$2,TRUE,$3)", [building, room, Date.now()]);
    await audit(req.user, "settings.room.create", `${building}/${room}`, null, req);
    res.status(201).json({ ok: true });
  });
  app.put("/api/admin/rooms", auth, need("admin"), async (req, res) => {
    const building = clean(req.body?.building, 1), room = clean(req.body?.room, 40), newRoom = clean(req.body?.newRoom, 40);
    if (!BUILDINGS.includes(building) || !room || !newRoom) return res.status(400).json({ error: "ข้อมูลเลขห้องไม่ถูกต้อง" });
    if (room !== newRoom && (await db.q("SELECT room FROM room_catalog WHERE building=$1 AND lower(room)=lower($2) AND room<>$3", [building, newRoom, room])).length)
      return res.status(409).json({ error: "มีเลขห้องใหม่นี้ในอาคารแล้ว" });
    const row = (await db.q("UPDATE room_catalog SET room=$1,active=TRUE WHERE building=$2 AND room=$3 RETURNING room", [newRoom, building, room]))[0];
    if (!row) return res.status(404).json({ error: "ไม่พบเลขห้อง" });
    await audit(req.user, "settings.room.rename", `${building}/${room}`, newRoom, req);
    res.json({ ok: true });
  });
  app.delete("/api/admin/rooms", auth, need("admin"), async (req, res) => {
    const building = clean(req.body?.building, 1), room = clean(req.body?.room, 40);
    if (!BUILDINGS.includes(building) || !room) return res.status(400).json({ error: "ข้อมูลเลขห้องไม่ถูกต้อง" });
    const row = (await db.q("UPDATE room_catalog SET active=FALSE WHERE building=$1 AND room=$2 RETURNING room", [building, room]))[0];
    if (!row) return res.status(404).json({ error: "ไม่พบเลขห้อง" });
    await audit(req.user, "settings.room.deactivate", `${building}/${room}`, null, req);
    res.json({ ok: true });
  });
  app.get("/api/users", auth, need("admin"), async (req, res) =>
    res.json({ users: await db.q("SELECT id,email,name,role,active FROM users ORDER BY created_at") }));
  app.put("/api/users/role", auth, need("admin"), async (req, res) => {
    const email = String(req.body?.email || "").toLowerCase().trim(), role = req.body?.role;
    if (!["user", "staff", "admin"].includes(role)) return res.status(400).json({ error: "บทบาทไม่ถูกต้อง" });
    const u = (await db.q("SELECT * FROM users WHERE email=$1", [email]))[0];
    if (!u) return res.status(404).json({ error: "ไม่พบผู้ใช้ (ผู้ใช้ต้องเข้าสู่ระบบอย่างน้อย 1 ครั้งก่อน)" });
    if (u.id === req.user.id && role !== "admin") return res.status(400).json({ error: "ไม่สามารถลดสิทธิ์ตัวเองได้" });
    await db.q("UPDATE users SET role=$1 WHERE id=$2", [role, u.id]);
    await audit(req.user, "user.role", email, `${u.role} -> ${role}`, req); res.json({ ok: true });
  });
  app.get("/api/audit", auth, need("admin"), async (req, res) =>
    res.json({ items: await db.q("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 300") }));

  app.use(express.static(path.join(__dirname, "../public")));
  app.use("/api", (req, res) => res.status(404).json({ error: "ไม่พบ" }));
  app.use((err, req, res, next) => {
    if (err.type === "entity.too.large") return res.status(413).json({ error: "ข้อมูลใหญ่เกินไป" });
    if (err instanceof SyntaxError) return res.status(400).json({ error: "รูปแบบข้อมูลไม่ถูกต้อง" });
    console.error(err); res.status(500).json({ error: "เกิดข้อผิดพลาดภายในระบบ" });
  });
  return app;
}
module.exports = { createApp };
