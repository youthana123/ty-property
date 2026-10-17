// TY Property API: Express + Render Postgres + Google Login
const express = require('express');
const crypto = require('crypto');
const { Pool, types } = require('pg');

types.setTypeParser(20, v => parseInt(v, 10)); // BIGINT -> number (ราคาเป็นบาท)

const app = express();
app.use(express.json({ limit: '1mb' }));

const ENV = process.env;

// แจ้งใน Logs ของ Render ถ้าตั้งค่าที่จำเป็นไว้ไม่ครบ (ไม่แสดงค่าลับ)
['DATABASE_URL', 'ADMIN_KEY', 'PUBLIC_API_URL', 'STORE_URL', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET']
  .filter(k => !ENV[k]).forEach(k => console.warn(`Missing env var: ${k}`));
const pool = new Pool({
  connectionString: ENV.DATABASE_URL,
  ssl: ENV.DB_SSL === 'false' ? false : { rejectUnauthorized: false },
});

// CORS: โดเมนหน้าร้านและหลังร้าน คั่นด้วยจุลภาค (ไม่มี / ท้าย)
const ORIGINS = (ENV.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const CALLBACK = `${ENV.PUBLIC_API_URL}/api/auth/google/callback`;
const pending = new Map(); // state ของ Google Login ใช้ได้ 10 นาที

app.use((req, res, next) => {
  const origin = req.get('origin');
  if (ORIGINS.includes('*')) res.set('Access-Control-Allow-Origin', '*');
  else if (origin && ORIGINS.includes(origin)) res.set({ 'Access-Control-Allow-Origin': origin, Vary: 'Origin' });
  res.set({
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,x-admin-key,Authorization',
  });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const num = v => Math.max(0, parseInt(String(v).replace(/[^\d]/g, ''), 10) || 0);
const idOf = req => parseInt(req.params.id, 10) || 0;
const TYPES = ['land', 'house', 'townhouse', 'condo', 'commercial'];
const STATUSES = ['available', 'reserved', 'sold'];
const LEAD_STATUSES = ['new', 'contacted', 'closed'];

// ลิงก์ Google Drive -> ลิงก์รูปที่แสดงบนเว็บได้ (ลิงก์รูปอื่นใช้ตามเดิม)
const photo = s => {
  const m = s.match(/drive\.google\.com\/.*?(?:\/d\/|[?&]id=)([\w-]+)/) || s.match(/^([\w-]{25,})$/);
  return m ? `https://lh3.googleusercontent.com/d/${m[1]}=w1200` : s;
};

const COLS = 'title, location, deed_type, rai, ngan, wah, price, status, description, images, property_type, bedrooms, bathrooms, usable_sqm, map_url';
const N = COLS.split(',').length;
const placeholders = () => Array.from({ length: N }, (_, i) => `$${i + 1}`).join(',');

const clean = b => ({
  title: String(b.title || '').trim(),
  location: String(b.location || '').trim(),
  deed_type: String(b.deed_type || '').trim(),
  rai: num(b.rai), ngan: num(b.ngan), wah: num(b.wah), price: num(b.price),
  status: STATUSES.includes(b.status) ? b.status : 'available',
  description: String(b.description || ''),
  images: Array.isArray(b.images) ? b.images.map(s => String(s).trim()).filter(Boolean).map(s => photo(s)).slice(0, 30) : [],
  property_type: TYPES.includes(b.property_type) ? b.property_type : 'land',
  bedrooms: num(b.bedrooms), bathrooms: num(b.bathrooms), usable_sqm: num(b.usable_sqm),
  map_url: /^https:\/\//.test(String(b.map_url || '').trim()) ? String(b.map_url).trim() : '',
});
const vals = d => [d.title, d.location, d.deed_type, d.rai, d.ngan, d.wah, d.price, d.status, d.description, d.images,
  d.property_type, d.bedrooms, d.bathrooms, d.usable_sqm, d.map_url];

// ตรวจผู้ใช้: แอดมิน (x-admin-key) หรือสมาชิกที่ล็อกอินด้วย Google (Bearer token)
async function viewer(req) {
  const key = req.get('x-admin-key');
  if (key && key === ENV.ADMIN_KEY) return { admin: true, userId: null };
  const m = (req.get('authorization') || '').match(/^Bearer ([a-f0-9]{64})$/);
  if (!m) return null;
  const { rows } = await pool.query(
    'SELECT u.id, u.name, u.picture FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1', [m[1]]);
  return rows[0] ? { admin: false, userId: rows[0].id, user: rows[0] } : null;
}

const requireViewer = wrap(async (req, res, next) => {
  const v = await viewer(req);
  if (!v) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' });
  req.viewer = v;
  next();
});

// ดูรายการได้โดยไม่ต้องล็อกอิน ถ้าล็อกอินอยู่จะได้สถานะถูกใจของตัวเองด้วย
const optionalViewer = wrap(async (req, res, next) => {
  req.viewer = (await viewer(req)) || { admin: false, userId: null };
  next();
});

const requireAdmin = (req, res, next) =>
  ENV.ADMIN_KEY && req.get('x-admin-key') === ENV.ADMIN_KEY
    ? next()
    : res.status(401).json({ error: 'รหัสผ่านไม่ถูกต้อง' });

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/auth', requireAdmin, (req, res) => res.json({ ok: true }));
app.get('/api/me', requireViewer, (req, res) => res.json(req.viewer.user || { name: 'ผู้ดูแล', picture: '' }));

app.post('/api/logout', requireViewer, wrap(async (req, res) => {
  if (req.viewer.user) await pool.query('DELETE FROM sessions WHERE token = $1', [req.get('authorization').slice(7)]);
  res.json({ ok: true });
}));

// Google Login: ยืนยันตัวตนด้วยบัญชี Google แล้วสร้าง session ให้เว็บ
app.get('/api/auth/google/start', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  pending.set(state, Date.now() + 10 * 60 * 1000);
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    response_type: 'code', client_id: ENV.GOOGLE_CLIENT_ID, redirect_uri: CALLBACK,
    scope: 'openid profile', state, prompt: 'select_account',
  }));
});

app.get('/api/auth/google/callback', wrap(async (req, res) => {
  const { code, state, error } = req.query;
  const valid = (pending.get(state) || 0) > Date.now();
  pending.delete(state);
  if (error) return res.status(400).send('ยกเลิกการเข้าสู่ระบบด้วย Google');
  if (!code || !valid) return res.status(400).send('การเข้าสู่ระบบหมดเวลา กรุณาลองใหม่อีกครั้ง');

  const t = await (await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: CALLBACK,
      client_id: ENV.GOOGLE_CLIENT_ID, client_secret: ENV.GOOGLE_CLIENT_SECRET,
    }),
  })).json();
  if (!t.access_token) {
    console.error('Google token exchange failed:', t.error, t.error_description);
    return res.status(400).send('เข้าสู่ระบบด้วย Google ไม่สำเร็จ');
  }

  const p = await (await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: { Authorization: 'Bearer ' + t.access_token },
  })).json();
  if (!p.sub) {
    console.error('Google userinfo failed:', p.error);
    return res.status(400).send('เข้าสู่ระบบด้วย Google ไม่สำเร็จ');
  }

  const { rows } = await pool.query(
    `INSERT INTO users (google_id, name, picture) VALUES ($1, $2, $3)
     ON CONFLICT (google_id) DO UPDATE SET name = EXCLUDED.name, picture = EXCLUDED.picture RETURNING id`,
    [p.sub, p.name || 'สมาชิก', p.picture || '']);
  const session = crypto.randomBytes(32).toString('hex');
  await pool.query('INSERT INTO sessions (token, user_id) VALUES ($1, $2)', [session, rows[0].id]);
  res.redirect(`${ENV.STORE_URL}/?session=${session}`);
}));

// รายการทรัพย์ (ไม่ต้องเข้าสู่ระบบ) ถ้าเข้าสู่ระบบแล้วจะมีสถานะถูกใจของผู้ใช้คนนั้น
const LIST_SQL = `SELECT l.*, EXISTS (SELECT 1 FROM likes k WHERE k.listing_id = l.id AND k.user_id = $1) AS liked
                  FROM listings l ORDER BY l.id DESC`;

app.get('/api/listings', optionalViewer, wrap(async (req, res) => {
  const { rows } = await pool.query(LIST_SQL, [req.viewer.userId]);
  res.json(rows);
}));

app.post('/api/listings/:id/like', requireViewer, wrap(async (req, res) => {
  const uid = req.viewer.userId;
  if (!uid) return res.status(403).json({ error: 'บัญชีผู้ดูแลไม่สามารถกดถูกใจได้' });
  const id = idOf(req);
  const del = await pool.query('DELETE FROM likes WHERE user_id = $1 AND listing_id = $2', [uid, id]);
  if (!del.rowCount) {
    await pool.query('INSERT INTO likes (user_id, listing_id) SELECT $1, id FROM listings WHERE id = $2', [uid, id]);
  }
  res.json({ liked: !del.rowCount });
}));

// คำขอจากลูกค้า: สนใจทรัพย์ (inquiry) และฝากขาย (sell) ต้องเข้าสู่ระบบและยินยอมตาม PDPA
app.post('/api/leads', requireViewer, wrap(async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim().slice(0, 100);
  const phone = String(b.phone || '').trim();
  if (!name || !/^[0-9+\-\s]{9,15}$/.test(phone)) {
    return res.status(400).json({ error: 'กรุณากรอกชื่อและเบอร์โทรศัพท์ให้ถูกต้อง' });
  }
  if (b.consent !== true) return res.status(400).json({ error: 'กรุณายินยอมให้เก็บข้อมูลก่อนส่ง' });

  const kind = b.kind === 'sell' ? 'sell' : 'inquiry';
  // ฝากขาย: คำนวณค่าบริการและยอดที่ผู้ขายได้รับบนเซิร์ฟเวอร์เสมอ (ไม่เชื่อค่าจากหน้าเว็บ)
  let asking = 0, rate = 0, fee = 0, net = 0;
  if (kind === 'sell') {
    asking = num(b.asking_price);
    if (!asking) return res.status(400).json({ error: 'กรุณาใส่ราคาที่ต้องการขาย' });
    rate = await commissionRate();
    fee = Math.round(asking * rate / 100);
    net = asking - fee;
  }
  await pool.query(
    `INSERT INTO leads (kind, listing_id, user_id, name, phone, message, property_type, location,
       asking_price, commission_rate, commission_amount, net_amount)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [kind, parseInt(b.listing_id, 10) || null, req.viewer.userId, name, phone,
      String(b.message || '').slice(0, 1000), String(b.property_type || '').slice(0, 30), String(b.location || '').slice(0, 200),
      asking, rate, fee, net]);
  res.status(201).json({ ok: true, asking_price: asking, commission_rate: rate, commission_amount: fee, net_amount: net });
}));

// อัตราค่าบริการที่หักจากราคาฝากขาย (ตั้งค่าได้จากหลังร้าน)
async function commissionRate() {
  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'commission_rate'");
  return Number(rows[0] && rows[0].value) || 0;
}

// หน้าร้านอ่านอัตราได้ทุกคน ส่วนการแก้ไขต้องใช้รหัสแอดมิน
app.get('/api/settings', wrap(async (req, res) => {
  res.json({ commission_rate: await commissionRate() });
}));

app.put('/api/settings', requireAdmin, wrap(async (req, res) => {
  const raw = String((req.body || {}).commission_rate ?? '').trim();
  const rate = Number(raw);
  if (!raw || !Number.isFinite(rate) || rate < 0 || rate > 100) {
    return res.status(400).json({ error: 'อัตราค่าบริการต้องเป็นตัวเลขระหว่าง 0 ถึง 100' });
  }
  const value = String(Math.round(rate * 100) / 100);
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('commission_rate', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, [value]);
  res.json({ commission_rate: Number(value) });
}));

app.get('/api/leads', requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT k.*, l.title AS listing_title FROM leads k LEFT JOIN listings l ON l.id = k.listing_id ORDER BY k.id DESC`);
  res.json(rows);
}));

app.put('/api/leads/:id', requireAdmin, wrap(async (req, res) => {
  const status = String(req.body.status || '');
  if (!LEAD_STATUSES.includes(status)) return res.status(400).json({ error: 'สถานะไม่ถูกต้อง' });
  await pool.query('UPDATE leads SET status = $1 WHERE id = $2', [status, idOf(req)]);
  res.json({ ok: true });
}));

app.delete('/api/leads/:id', requireAdmin, wrap(async (req, res) => {
  await pool.query('DELETE FROM leads WHERE id = $1', [idOf(req)]);
  res.json({ ok: true });
}));

// งานของแอดมิน: เพิ่ม แก้ไข ลบทรัพย์
app.post('/api/listings', requireAdmin, wrap(async (req, res) => {
  const d = clean(req.body);
  if (!d.title) return res.status(400).json({ error: 'กรุณาใส่ชื่อประกาศ' });
  const { rows } = await pool.query(`INSERT INTO listings (${COLS}) VALUES (${placeholders()}) RETURNING *`, vals(d));
  res.status(201).json(rows[0]);
}));

app.put('/api/listings/:id', requireAdmin, wrap(async (req, res) => {
  const d = clean(req.body);
  if (!d.title) return res.status(400).json({ error: 'กรุณาใส่ชื่อประกาศ' });
  const { rows } = await pool.query(
    `UPDATE listings SET (${COLS}, updated_at) = (${placeholders()}, now()) WHERE id = $${N + 1} RETURNING *`,
    [...vals(d), idOf(req)]);
  if (rows[0]) res.json(rows[0]);
  else res.status(404).json({ error: 'ไม่พบรายการ' });
}));

app.delete('/api/listings/:id', requireAdmin, wrap(async (req, res) => {
  await pool.query('DELETE FROM listings WHERE id = $1', [idOf(req)]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' });
});

// ข้อมูลตัวอย่างจากเอกสาร TY PRIME (ขนาดและรายละเอียดบางรายการเป็นค่าสมมติ แก้ไขได้จากหลังร้าน)
const SAMPLES = [
  { title: 'ที่ดินทองหล่อ สุขุมวิท 55 (ตัวอย่าง)', location: 'สุขุมวิท 55 ทองหล่อ กรุงเทพฯ', deed_type: 'น.ส.4 จ.', ngan: 2, price: 265000000, description: 'ข้อมูลตัวอย่าง กรุณาแก้ไขให้ตรงกับแปลงจริง' },
  { title: 'ที่ดินเจริญกรุง ริมเจ้าพระยา (B-017)', location: 'เจริญกรุง ริมแม่น้ำเจ้าพระยา กรุงเทพฯ', deed_type: 'น.ส.4 จ.', rai: 5, wah: 80, price: 420000000, description: 'ข้อมูลตัวอย่าง กรุณาแก้ไขให้ตรงกับแปลงจริง' },
  { title: 'ที่ดิน EEC ศรีราชา (ตัวอย่าง)', location: 'ศรีราชา ชลบุรี', deed_type: 'น.ส.3 ก.', rai: 2, ngan: 1, wah: 50, price: 185000000, status: 'reserved', description: 'ข้อมูลตัวอย่าง กรุณาแก้ไขให้ตรงกับแปลงจริง' },
  { title: 'บ้านเดี่ยว 2 ชั้น ลาดพร้าว (ตัวอย่าง)', location: 'ลาดพร้าว กรุงเทพฯ', deed_type: 'โฉนด', property_type: 'house', ngan: 1, price: 12500000, bedrooms: 3, bathrooms: 3, usable_sqm: 240, description: 'ข้อมูลตัวอย่าง กรุณาแก้ไขให้ตรงกับบ้านจริง' },
];

const TABLES = [
  `CREATE TABLE IF NOT EXISTS listings (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    deed_type TEXT NOT NULL DEFAULT '',
    rai INT NOT NULL DEFAULT 0,
    ngan INT NOT NULL DEFAULT 0,
    wah INT NOT NULL DEFAULT 0,
    price BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'available',
    description TEXT NOT NULL DEFAULT '',
    images TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `ALTER TABLE listings ADD COLUMN IF NOT EXISTS property_type TEXT NOT NULL DEFAULT 'land'`,
  `ALTER TABLE listings ADD COLUMN IF NOT EXISTS bedrooms INT NOT NULL DEFAULT 0`,
  `ALTER TABLE listings ADD COLUMN IF NOT EXISTS bathrooms INT NOT NULL DEFAULT 0`,
  `ALTER TABLE listings ADD COLUMN IF NOT EXISTS usable_sqm INT NOT NULL DEFAULT 0`,
  `ALTER TABLE listings ADD COLUMN IF NOT EXISTS map_url TEXT NOT NULL DEFAULT ''`,
  `CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    google_id TEXT UNIQUE,
    line_id TEXT UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    picture TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT UNIQUE`,
  `ALTER TABLE users ALTER COLUMN line_id DROP NOT NULL`,
  `CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS likes (
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    listing_id INT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, listing_id)
  )`,
  `CREATE TABLE IF NOT EXISTS leads (
    id SERIAL PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT 'inquiry',
    listing_id INT REFERENCES listings(id) ON DELETE SET NULL,
    user_id INT REFERENCES users(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    property_type TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new',
    consent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
  `ALTER TABLE leads ADD COLUMN IF NOT EXISTS asking_price BIGINT NOT NULL DEFAULT 0`,
  `ALTER TABLE leads ADD COLUMN IF NOT EXISTS commission_rate NUMERIC(5,2) NOT NULL DEFAULT 0`,
  `ALTER TABLE leads ADD COLUMN IF NOT EXISTS commission_amount BIGINT NOT NULL DEFAULT 0`,
  `ALTER TABLE leads ADD COLUMN IF NOT EXISTS net_amount BIGINT NOT NULL DEFAULT 0`,
];

async function init() {
  for (const sql of TABLES) await pool.query(sql);
  await pool.query("INSERT INTO settings (key, value) VALUES ('commission_rate', '3') ON CONFLICT (key) DO NOTHING");
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM listings');
  if (rows[0].n > 0) return;
  for (const s of SAMPLES) {
    await pool.query(`INSERT INTO listings (${COLS}) VALUES (${placeholders()})`, vals(clean(s)));
  }
}

init()
  .then(() => app.listen(ENV.PORT || 10000, () => console.log('API ready')))
  .catch(err => {
    console.error('Database init failed:', err);
    process.exit(1);
  });
