const test = require("node:test"), assert = require("node:assert/strict");
const { open } = require("../src/db"), { createApp } = require("../src/app");
const PNG = "data:image/png;base64," + Buffer.concat([Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]), Buffer.alloc(40)]).toString("base64");
let srv, base, db;
test.before(async () => {
  db = await open();
  const app = createApp({ db, secret: "t".repeat(32), authMode: "dev", devLogin: true, allowedDomain: "uni.ac.th",
    adminEmails: ["boss@uni.ac.th"], notify: async () => {}, createLimit: 50 });
  await new Promise(r => { srv = app.listen(0, r); }); base = "http://127.0.0.1:" + srv.address().port;
});
test.after(async () => { srv.close(); await db.close(); });
async function login(email) {
  const r = await fetch(base + "/api/dev-login", { method: "POST", headers: { "content-type": "application/json", "x-requested-with": "fixu" }, body: JSON.stringify({ email, name: email.split("@")[0] }) });
  const c = (r.headers.get("set-cookie") || "").split(";")[0];
  return { status: r.status, call: (m, u, b) => fetch(base + u, { method: m, headers: { "content-type": "application/json", "x-requested-with": "fixu", cookie: c }, body: b ? JSON.stringify(b) : undefined }) };
}
const good = { type: "ไฟฟ้า", building: "A", room: "A3", description: "ไฟดับ", images: [PNG] };

test("ต้องล็อกอินก่อน และต้องมี header กัน CSRF", async () => {
  assert.equal((await fetch(base + "/api/tickets")).status, 401);
  const r = await fetch(base + "/api/dev-login", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(r.status, 403);
});
test("จำกัดโดเมนอีเมลมหาวิทยาลัย", async () => assert.equal((await login("x@gmail.com")).status, 403));
test("ผู้แจ้งสร้าง Ticket พร้อมรูป และเห็นเฉพาะของตนเอง", async () => {
  const a = await login("a@uni.ac.th"), b = await login("b@uni.ac.th");
  const c = await a.call("POST", "/api/tickets", good); assert.equal(c.status, 201);
  const list = await (await a.call("GET", "/api/tickets")).json(); assert.equal(list.tickets.length, 1);
  const img = list.tickets[0].im[0]; assert.equal((await a.call("GET", img)).status, 200);
  assert.equal((await b.call("GET", img)).status, 404);
  assert.equal((await (await b.call("GET", "/api/tickets")).json()).tickets.length, 0);
});
test("ตรวจข้อมูลนำเข้า", async () => {
  const a = await login("a@uni.ac.th");
  for (const bad of [{ ...good, building: "Z" }, { ...good, description: "  " }, { ...good, images: [PNG, PNG, PNG, PNG] },
    { ...good, images: ["data:image/png;base64," + Buffer.from("not an image").toString("base64")] }, { ...good, images: ["data:text/html;base64,PGI+"] }])
    assert.equal((await a.call("POST", "/api/tickets", bad)).status, 400);
});
test("สิทธิ์และวงจรงาน: ผู้แจ้งเปลี่ยนสถานะไม่ได้ เจ้าหน้าที่ทำตามลำดับ ปิดงานต้องมีบันทึก", async () => {
  const boss = await login("boss@uni.ac.th"), a = await login("a@uni.ac.th"), s = await login("staff@uni.ac.th");
  assert.equal((await boss.call("PUT", "/api/users/role", { email: "staff@uni.ac.th", role: "staff" })).status, 200);
  const id = (await (await a.call("GET", "/api/tickets")).json()).tickets[0].id;
  const st = (c, status, extra = {}) => c.call("POST", `/api/tickets/${id}/status`, { status, ...extra });
  assert.equal((await st(a, 1, { assignee: 1 })).status, 403);
  assert.equal((await st(s, 2, { assignee: 1 })).status, 400);
  assert.equal((await st(s, 1)).status, 400);
  assert.equal((await st(s, 1, { assignee: 1 })).status, 200);
  assert.equal((await st(s, 2)).status, 200);
  assert.equal((await st(s, 3)).status, 400);
  assert.equal((await st(s, 3, { note: "เปลี่ยนหลอดไฟแล้ว" })).status, 200);
  const n = await (await a.call("GET", "/api/notifications")).json(); assert.ok(n.items.length >= 4);
});
test("เปิดซ้ำได้เฉพาะเจ้าของ Ticket ที่ปิดแล้ว", async () => {
  const a = await login("a@uni.ac.th"), b = await login("b@uni.ac.th");
  const id = (await (await a.call("GET", "/api/tickets")).json()).tickets[0].id;
  assert.equal((await b.call("POST", `/api/tickets/${id}/reopen`)).status, 404);
  assert.equal((await a.call("POST", `/api/tickets/${id}/reopen`)).status, 200);
  assert.equal((await (await a.call("GET", "/api/tickets")).json()).tickets[0].ops.s, 0);
  assert.equal((await a.call("POST", `/api/tickets/${id}/reopen`)).status, 400);
});
test("บันทึกกิจกรรมดูได้เฉพาะผู้ดูแลระบบ และสถิติรวมใช้ได้ทุกคน", async () => {
  const boss = await login("boss@uni.ac.th"), s = await login("staff@uni.ac.th"), a = await login("a@uni.ac.th");
  assert.equal((await s.call("GET", "/api/audit")).status, 403);
  const j = await (await boss.call("GET", "/api/audit")).json(); assert.ok(j.items.some(x => x.action === "ticket.status"));
  assert.equal((await a.call("GET", "/api/users")).status, 403);
  assert.equal((await (await a.call("GET", "/api/stats")).json()).counts.a, 1);
});
test("ลดสิทธิ์ตัวเองไม่ได้", async () => {
  const boss = await login("boss@uni.ac.th");
  assert.equal((await boss.call("PUT", "/api/users/role", { email: "boss@uni.ac.th", role: "user" })).status, 400);
});

test("โหมดทดสอบ (local): ต้องมีรหัสเข้าร่วม และปิด dev-login", async () => {
  const db2 = await open(), app = createApp({ db: db2, secret: "t".repeat(32), authMode: "local", pilotCode: "pilot-1234", adminEmails: ["a@x.com"], loginLimit: 5, notify: async () => {} });
  const s = await new Promise(r => { const x = app.listen(0, () => r(x)); }), b = "http://127.0.0.1:" + s.address().port;
  const post = (u, body) => fetch(b + u, { method: "POST", headers: { "content-type": "application/json", "x-requested-with": "fixu" }, body: JSON.stringify(body) });
  assert.equal((await post("/api/dev-login", { email: "a@x.com" })).status, 404);
  assert.equal((await post("/api/local-login", { email: "a@x.com", code: "wrong" })).status, 403);
  const ok = await post("/api/local-login", { email: "a@x.com", name: "ผู้ทดสอบ", code: "pilot-1234" });
  assert.equal(ok.status, 200);
  const me = await (await fetch(b + "/api/me", { headers: { cookie: ok.headers.get("set-cookie").split(";")[0] } })).json();
  assert.equal(me.role, "admin");
  for (let i = 0; i < 6; i++) await post("/api/local-login", { email: "a@x.com", code: "x" });
  assert.equal((await post("/api/local-login", { email: "a@x.com", code: "pilot-1234" })).status, 429);
  s.close();
});

test("ตรวจค่าตั้งค่าก่อนใช้งานจริง (production)", () => {
  const { buildConfig } = require("../src/config");
  const ok = { NODE_ENV: "production", AUTH_MODE: "local", SESSION_SECRET: "s".repeat(40), PILOT_CODE: "abcd1234", ADMIN_EMAILS: "a@x.com", DATABASE_URL: "postgresql://x" };
  assert.doesNotThrow(() => buildConfig(ok));
  assert.throws(() => buildConfig({ ...ok, DATABASE_URL: "" }), /DATABASE_URL/);
  assert.throws(() => buildConfig({ ...ok, PILOT_CODE: "short" }), /PILOT_CODE/);
  assert.throws(() => buildConfig({ ...ok, AUTH_MODE: "dev" }), /AUTH_MODE/);
});
