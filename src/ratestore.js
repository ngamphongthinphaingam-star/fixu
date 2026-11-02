// ที่เก็บตัวนับ rate limit ใน PostgreSQL — จำเป็นบน serverless (Vercel) เพราะหน่วยความจำไม่ถูกแชร์ระหว่างอินสแตนซ์
class PgStore {
  constructor(db, prefix) { this.db = db; this.p = prefix; }
  init(o) { this.win = o.windowMs; }
  async increment(key) {
    const now = Date.now();
    const r = await this.db.q(
      `INSERT INTO rate_limits(key,hits,reset_at) VALUES($1,1,$2::bigint)
       ON CONFLICT(key) DO UPDATE SET
         hits = CASE WHEN rate_limits.reset_at <= $3::bigint THEN 1 ELSE rate_limits.hits + 1 END,
         reset_at = CASE WHEN rate_limits.reset_at <= $3::bigint THEN $2::bigint ELSE rate_limits.reset_at END
       RETURNING hits, reset_at`, [this.p + key, now + this.win, now]);
    return { totalHits: r[0].hits, resetTime: new Date(r[0].reset_at) };
  }
  async decrement(key) { await this.db.q("UPDATE rate_limits SET hits=GREATEST(hits-1,0) WHERE key=$1", [this.p + key]); }
  async resetKey(key) { await this.db.q("DELETE FROM rate_limits WHERE key=$1", [this.p + key]); }
}
module.exports = { PgStore };
