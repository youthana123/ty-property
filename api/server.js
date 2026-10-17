// TY Property API: Express + Render Postgres
const express = require('express');
const { Pool, types } = require('pg');

types.setTypeParser(20, v => parseInt(v, 10)); // BIGINT -> number (ราคาเป็นบาท)

const app = express();
app.use(express.json({ limit: '1mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false },
});

// CORS: ใส่โดเมนของหน้าร้านและหลังร้าน คั่นด้วยเครื่องหมายจุลภาค (ไม่มี / ท้ายชื่อ)
const ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
app.use((req, res, next) => {
  const origin = req.get('origin');
  if (ORIGINS.includes('*')) res.set('Access-Control-Allow-Origin', '*');
  else if (origin && ORIGINS.includes(origin)) res.set({ 'Access-Control-Allow-Origin': origin, Vary: 'Origin' });
  res.set({
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,x-admin-key',
  });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const requireAdmin = (req, res, next) =>
  process.env.ADMIN_KEY && req.get('x-admin-key') === process.env.ADMIN_KEY
    ? next()
    : res.status(401).json({ error: 'รหัสผ่านไม่ถูกต้อง' });

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const num = v => Math.max(0, parseInt(String(v).replace(/[^\d]/g, ''), 10) || 0);
const STATUSES = ['available', 'reserved', 'sold'];

const clean = b => ({
  title: String(b.title || '').trim(),
  location: String(b.location || '').trim(),
  deed_type: String(b.deed_type || '').trim(),
  rai: num(b.rai), ngan: num(b.ngan), wah: num(b.wah), price: num(b.price),
  status: STATUSES.includes(b.status) ? b.status : 'available',
  description: String(b.description || ''),
  images: Array.isArray(b.images) ? b.images.map(String).filter(Boolean).slice(0, 20) : [],
});
const COLS = 'title, location, deed_type, rai, ngan, wah, price, status, description, images';
const vals = d => [d.title, d.location, d.deed_type, d.rai, d.ngan, d.wah, d.price, d.status, d.description, d.images];
const notFound = res => res.status(404).json({ error: 'ไม่พบรายการ' });

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/auth', requireAdmin, (req, res) => res.json({ ok: true }));

app.get('/api/listings', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM listings ORDER BY id DESC');
  res.json(rows);
}));

app.get('/api/listings/:id', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM listings WHERE id = $1', [parseInt(req.params.id, 10) || 0]);
  rows[0] ? res.json(rows[0]) : notFound(res);
}));

app.post('/api/listings', requireAdmin, wrap(async (req, res) => {
  const d = clean(req.body);
  if (!d.title) return res.status(400).json({ error: 'กรุณาใส่ชื่อแปลง' });
  const { rows } = await pool.query(
    `INSERT INTO listings (${COLS}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`, vals(d));
  res.status(201).json(rows[0]);
}));

app.put('/api/listings/:id', requireAdmin, wrap(async (req, res) => {
  const d = clean(req.body);
  if (!d.title) return res.status(400).json({ error: 'กรุณาใส่ชื่อแปลง' });
  const { rows } = await pool.query(
    `UPDATE listings SET (${COLS}, updated_at) = ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now()) WHERE id = $11 RETURNING *`,
    [...vals(d), parseInt(req.params.id, 10) || 0]);
  rows[0] ? res.json(rows[0]) : notFound(res);
}));

app.delete('/api/listings/:id', requireAdmin, wrap(async (req, res) => {
  await pool.query('DELETE FROM listings WHERE id = $1', [parseInt(req.params.id, 10) || 0]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' });
});

// ข้อมูลตัวอย่างจากเอกสาร TY PRIME (ขนาดบางแปลงเป็นค่าสมมติ แก้ไขได้จากหลังร้าน)
const SAMPLES = [
  { title: 'ที่ดินทองหล่อ สุขุมวิท 55 (ตัวอย่าง)', location: 'สุขุมวิท 55 ทองหล่อ กรุงเทพฯ', deed_type: 'น.ส.4 จ.', ngan: 2, price: 265000000, description: 'ข้อมูลตัวอย่าง กรุณาแก้ไขให้ตรงกับแปลงจริง' },
  { title: 'ที่ดินเจริญกรุง ริมเจ้าพระยา (B-017)', location: 'เจริญกรุง ริมแม่น้ำเจ้าพระยา กรุงเทพฯ', deed_type: 'น.ส.4 จ.', rai: 5, wah: 80, price: 420000000, description: 'ข้อมูลตัวอย่าง กรุณาแก้ไขให้ตรงกับแปลงจริง' },
  { title: 'ที่ดิน EEC ศรีราชา (ตัวอย่าง)', location: 'ศรีราชา ชลบุรี', deed_type: 'น.ส.3 ก.', rai: 2, ngan: 1, wah: 50, price: 185000000, status: 'reserved', description: 'ข้อมูลตัวอย่าง กรุณาแก้ไขให้ตรงกับแปลงจริง' },
];

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS listings (
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
  )`);
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM listings');
  if (rows[0].n > 0) return;
  for (const s of SAMPLES) {
    await pool.query(`INSERT INTO listings (${COLS}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, vals(clean(s)));
  }
}

init()
  .then(() => app.listen(process.env.PORT || 10000, () => console.log('API ready')))
  .catch(err => {
    console.error('Database init failed:', err);
    process.exit(1);
  });
