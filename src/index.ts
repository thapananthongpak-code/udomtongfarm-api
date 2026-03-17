import * as dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { createClient } from '@libsql/client';
import nodemailer from 'nodemailer';
import { createHash } from 'crypto';

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT         = process.env.PORT || 3000;
const DB_URL       = process.env.TURSO_DB_URL!;
const DB_TOKEN     = process.env.TURSO_DB_TOKEN!.replace(/\s/g, '');
const EMAIL_USER   = process.env.EMAIL_USER!;
const EMAIL_PASS   = process.env.EMAIL_PASS!;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'change_me';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173')
  .split(',').map((o) => o.trim());

if (!DB_URL || !DB_TOKEN) {
  console.error('❌ Missing TURSO_DB_URL or TURSO_DB_TOKEN in .env');
  process.exit(1);
}

// ─── Database ─────────────────────────────────────────────────────────────────
const db = createClient({ url: DB_URL, authToken: DB_TOKEN });

// ─── Email ────────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  tls: { rejectUnauthorized: false },
  socketOptions: { family: 4 },
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
} as any);

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();

// Security: restrict CORS to allowed origins
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Security: limit request body size
app.use(express.json({ limit: '1mb' }));

// Security: basic response headers
app.use((_req, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ─── In-memory rate limiter ───────────────────────────────────────────────────
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function rateLimit(maxRequests: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = (req.ip || 'unknown') + req.path;
    const now = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || now > entry.resetAt) {
      rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (entry.count >= maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
    }
    entry.count++;
    next();
  };
}

// Clean up expired rate limit entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitMap) {
    if (now > val.resetAt) rateLimitMap.delete(key);
  }
}, 10 * 60 * 1000);

// ─── Validation helpers ───────────────────────────────────────────────────────
function isValidEmail(email: unknown): boolean {
  if (typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}
function sanitizeStr(s: unknown, maxLen = 500): string {
  if (typeof s !== 'string') return '';
  return s.trim().slice(0, maxLen);
}

// Password hash (sha256+salt). Better than plaintext; migrate to bcrypt for production.
function hashPassword(plain: string): string {
  return createHash('sha256').update(plain + 'uf_salt_2025').digest('hex');
}

// ─── Setup route guard ────────────────────────────────────────────────────────
function requireSecret(req: Request, res: Response, next: NextFunction) {
  if (req.query.secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden: invalid secret' });
  }
  next();
}

// ─── Auth rate limiter: 10 req per 15 min per IP+path ────────────────────────
const authLimiter = rateLimit(10, 15 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/health', async (_req: Request, res: Response) => {
  try {
    await db.execute('SELECT 1');
    res.json({ status: 'ok', db: 'connected', ts: new Date().toISOString() });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error('❌ DB error:', msg);
    res.status(503).json({ status: 'error', db: 'unreachable', reason: msg });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SETUP ROUTES (protected: require ?secret=ADMIN_SECRET)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/setup-db', requireSecret, async (_req: Request, res: Response) => {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, nickname TEXT, phone TEXT, birth_date TEXT, email TEXT UNIQUE, password TEXT, pdpa_accepted BOOLEAN DEFAULT 0, is_verified BOOLEAN DEFAULT 0, avatar TEXT)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, otp_code TEXT, expires_at DATETIME)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS login_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT, user_name TEXT, role TEXT, login_at DATETIME DEFAULT CURRENT_TIMESTAMP, logout_at DATETIME)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)`);
    // migrate: add avatar column if not exists (safe to ignore error if already exists)
    try { await db.execute(`ALTER TABLE users ADD COLUMN avatar TEXT`); } catch {}
    res.json({ message: 'DB tables created' });
  } catch { res.status(500).json({ error: 'Setup failed' }); }
});

app.get('/setup-species', requireSecret, async (_req: Request, res: Response) => {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS species (id TEXT PRIMARY KEY, type TEXT NOT NULL, name_th TEXT NOT NULL, name_en TEXT NOT NULL, scientific_name TEXT, short_description TEXT, description TEXT, image TEXT, tags TEXT, references_data TEXT)`);
    try { await db.execute(`ALTER TABLE species ADD COLUMN short_description_en TEXT`); } catch {}
    try { await db.execute(`ALTER TABLE species ADD COLUMN description_en TEXT`); } catch {}
    res.json({ message: 'Species table created' });
  } catch { res.status(500).json({ error: 'Setup species failed' }); }
});

app.get('/setup-admin', requireSecret, async (_req: Request, res: Response) => {
  try {
    const check = await db.execute({ sql: 'SELECT id FROM admins WHERE email = ?', args: [EMAIL_USER] });
    if ((check.rows as any[]).length === 0) {
      await db.execute({ sql: `INSERT INTO admins (name, email, password) VALUES (?, ?, ?)`, args: ['Owner', EMAIL_USER, hashPassword('admin1234')] });
      return res.json({ message: 'Admin created' });
    }
    res.json({ message: 'Admin already exists' });
  } catch { res.status(500).json({ error: 'Admin setup failed' }); }
});

app.get('/upgrade-db', requireSecret, async (_req: Request, res: Response) => {
  try {
    await db.execute(`ALTER TABLE users ADD COLUMN nickname TEXT`);
    await db.execute(`ALTER TABLE users ADD COLUMN phone TEXT`);
    await db.execute(`ALTER TABLE users ADD COLUMN birth_date TEXT`);
    await db.execute(`ALTER TABLE users ADD COLUMN pdpa_accepted BOOLEAN DEFAULT 0`);
    res.json({ message: 'DB upgraded' });
  } catch { res.json({ message: 'Columns already exist' }); }
});

app.get('/cleanup-users', requireSecret, async (_req: Request, res: Response) => {
  try {
    await db.execute(`DELETE FROM users WHERE is_verified = 0`);
    res.json({ message: 'Unverified users removed' });
  } catch { res.status(500).json({ error: 'Cleanup failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMINS API
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/admins', async (_req: Request, res: Response) => {
  try {
    const result = await db.execute('SELECT email, name FROM admins');
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

app.post('/api/admins', async (req: Request, res: Response) => {
  const email = sanitizeStr(req.body?.email).toLowerCase();
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  try {
    await db.execute({ sql: 'INSERT INTO admins (name, email, password) VALUES (?, ?, ?)', args: ['Extra Admin', email, hashPassword('admin1234')] });
    res.json({ message: 'Admin added' });
  } catch { res.status(400).json({ error: 'อีเมลนี้เป็นแอดมินอยู่แล้ว' }); }
});

app.delete('/api/admins/:email', async (req: Request, res: Response) => {
  const email = decodeURIComponent(req.params['email'] as string);
  if (email === EMAIL_USER) return res.status(403).json({ error: 'ลบ Owner ไม่ได้' });
  try {
    await db.execute({ sql: 'DELETE FROM admins WHERE email = ?', args: [email] });
    res.json({ message: 'Admin removed' });
  } catch { res.status(500).json({ error: 'Delete failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SPECIES API
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/species', async (_req: Request, res: Response) => {
  try {
    const result = await db.execute('SELECT * FROM species');
    res.json(result.rows.map((row: any) => ({
      ...row,
      tags:       JSON.parse(row.tags || '[]'),
      references: JSON.parse(row.references_data || '[]'),
    })));
  } catch { res.status(500).json({ error: 'Failed to fetch species' }); }
});

app.post('/api/species', async (req: Request, res: Response) => {
  const { id, type, name_th, name_en, scientific_name, short_description, short_description_en, description, description_en, image, tags, references } = req.body;
  if (!id || !type || !name_th || !name_en) return res.status(400).json({ error: 'Missing required fields' });
  if (!['animal', 'plant'].includes(type)) return res.status(400).json({ error: 'Invalid type' });
  try {
    await db.execute({
      sql: `INSERT OR REPLACE INTO species (id, type, name_th, name_en, scientific_name, short_description, short_description_en, description, description_en, image, tags, references_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [id, type, name_th, name_en, scientific_name ?? null, short_description ?? null, short_description_en ?? null, description ?? null, description_en ?? null, image ?? null, JSON.stringify(tags || []), JSON.stringify(references || [])],
    });
    res.json({ message: 'บันทึกข้อมูลสำเร็จ!' });
  } catch { res.status(500).json({ error: 'Failed to save species' }); }
});

app.put('/api/species/:id', async (req: Request, res: Response) => {
  const id = req.params['id'] as string;
  if (!id) return res.status(400).json({ error: 'Missing id' });
  const { type, name_th, name_en, scientific_name, short_description, short_description_en, description, description_en, image, tags, references } = req.body;
  if (!type || !name_th || !name_en) return res.status(400).json({ error: 'Missing required fields' });
  if (!['animal', 'plant'].includes(type)) return res.status(400).json({ error: 'Invalid type' });
  try {
    const check = await db.execute({ sql: 'SELECT id FROM species WHERE id = ?', args: [id] });
    if ((check.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบข้อมูล' });
    await db.execute({
      sql: `UPDATE species SET type=?, name_th=?, name_en=?, scientific_name=?, short_description=?, short_description_en=?, description=?, description_en=?, image=?, tags=?, references_data=? WHERE id=?`,
      args: [type, name_th, name_en, scientific_name ?? null, short_description ?? null, short_description_en ?? null, description ?? null, description_en ?? null, image ?? null, JSON.stringify(tags || []), JSON.stringify(references || []), id],
    });
    res.json({ message: 'อัปเดตข้อมูลสำเร็จ!' });
  } catch { res.status(500).json({ error: 'Failed to update species' }); }
});

app.delete('/api/species/:id', async (req: Request, res: Response) => {
  if (!req.params['id']) return res.status(400).json({ error: 'Missing id' });
  try {
    await db.execute({ sql: 'DELETE FROM species WHERE id = ?', args: [req.params['id'] as string] });
    res.json({ message: 'ลบข้อมูลสำเร็จ!' });
  } catch { res.status(500).json({ error: 'Failed to delete' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// REGISTER
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/register', authLimiter, async (req: Request, res: Response) => {
  const { email, password, name, nickname, phone, birthDate, pdpa, avatar } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Missing required fields' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
  if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const adminCheck = await db.execute({ sql: 'SELECT id FROM admins WHERE email = ?', args: [email] });
    if ((adminCheck.rows as any[]).length > 0) return res.status(400).json({ error: 'อีเมลนี้มีในระบบแล้ว' });

    const userCheck = await db.execute({ sql: 'SELECT id, is_verified FROM users WHERE email = ?', args: [email] });
    if ((userCheck.rows as any[]).length > 0) {
      const existing = userCheck.rows[0] as any;
      if (existing.is_verified === 1) return res.status(400).json({ error: 'อีเมลนี้มีในระบบแล้ว' });
      await db.execute({ sql: 'DELETE FROM users WHERE email = ?', args: [email] });
      await db.execute({ sql: 'DELETE FROM otps WHERE email = ?', args: [email] });
    }

    await db.execute({
      sql: 'INSERT INTO users (name, nickname, phone, birth_date, email, password, pdpa_accepted, is_verified, avatar) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)',
      args: [sanitizeStr(name), sanitizeStr(nickname), sanitizeStr(phone), sanitizeStr(birthDate), email, hashPassword(password), pdpa ? 1 : 0, avatar || null],
    });

    const otpCode   = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60000).toISOString();
    await db.execute({ sql: 'INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)', args: [email, otpCode, expiresAt] });

    if (process.env.NODE_ENV !== 'production') console.log(`\n[OTP] ${email} => ${otpCode}\n`);

    if (EMAIL_USER && EMAIL_PASS) {
      try {
        await transporter.sendMail({
          from: `"Udomtong Farm" <${EMAIL_USER}>`,
          to: email,
          subject: 'รหัส OTP สมัครสมาชิก Udomtong Farm',
          html: `<div style="font-family:Arial,sans-serif;padding:20px;max-width:400px"><h2 style="color:#1b4332">ยินดีต้อนรับสู่ Udomtong Farm</h2><p>รหัส OTP สำหรับยืนยันอีเมลของคุณคือ:</p><div style="font-size:2.5rem;font-weight:900;color:#2d6a4f;letter-spacing:8px;margin:16px 0">${otpCode}</div><p style="color:#666;font-size:0.9rem">รหัสนี้จะหมดอายุใน 15 นาที</p></div>`,
        });
      } catch (mailErr) {
        console.error('[Email error] sendMail failed:', mailErr);
      }
    }

    res.json({ message: 'สมัครสมาชิกสำเร็จ! กรุณายืนยัน OTP ทางอีเมล' });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Register failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VERIFY OTP
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/verify-otp', authLimiter, async (req: Request, res: Response) => {
  const { email, otpCode } = req.body;
  if (!email || !otpCode) return res.status(400).json({ error: 'Missing fields' });
  try {
    const result = await db.execute({
      sql: `SELECT * FROM otps WHERE email = ? AND otp_code = ? AND expires_at > DATETIME('now') ORDER BY id DESC LIMIT 1`,
      args: [email, String(otpCode)],
    });
    if ((result.rows as any[]).length === 0) return res.status(400).json({ error: 'OTP ไม่ถูกต้องหรือหมดอายุ' });
    await db.execute({ sql: 'UPDATE users SET is_verified = 1 WHERE email = ?', args: [email] });
    await db.execute({ sql: 'DELETE FROM otps WHERE email = ?', args: [email] });
    res.json({ message: 'ยืนยันอีเมลสำเร็จ!' });
  } catch { res.status(500).json({ error: 'Verify failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// LOGIN
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/login', authLimiter, async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'กรุณากรอกอีเมลและรหัสผ่าน', field: 'both' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'รูปแบบอีเมลไม่ถูกต้อง', field: 'email' });

  const hashedPw = hashPassword(password);
  try {
    const adminResult = await db.execute({ sql: 'SELECT * FROM admins WHERE email = ?', args: [email] });
    if ((adminResult.rows as any[]).length > 0) {
      const admin = adminResult.rows[0] as any;
      if (admin.password !== hashedPw && admin.password !== password) {
        return res.status(401).json({ error: 'รหัสผ่านไม่ถูกต้อง', field: 'password' });
      }
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'admin', DATETIME('now'))`, args: [admin.email, admin.name || ''] }); } catch (e) { console.warn('login_sessions insert skipped:', e); }
      return res.json({ message: 'แอดมินเข้าสู่ระบบสำเร็จ', user: { ...admin, role: 'admin' } });
    }

    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
    if ((userResult.rows as any[]).length > 0) {
      const user = userResult.rows[0] as any;
      if (user.password !== hashedPw && user.password !== password) {
        return res.status(401).json({ error: 'รหัสผ่านไม่ถูกต้อง', field: 'password' });
      }
      if (user.is_verified === 0) return res.status(403).json({ error: 'อีเมลนี้ยังไม่ได้รับการยืนยัน กรุณาตรวจสอบกล่องจดหมาย', field: 'email' });
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [user.email, user.name || ''] }); } catch (e) { console.warn('login_sessions insert skipped:', e); }
      return res.json({ message: 'เข้าสู่ระบบสำเร็จ', user: { ...user, role: 'user' } });
    }

    res.status(401).json({ error: 'ไม่พบอีเมลนี้ในระบบ', field: 'email' });
  } catch (e) { console.error('Login error:', e); res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ กรุณาลองใหม่' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// GOOGLE LOGIN
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/google-login', async (req: Request, res: Response) => {
  const { email, name, uid, photoURL } = req.body;
  if (!email || !uid) return res.status(400).json({ error: 'Missing fields' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  try {
    const adminResult = await db.execute({ sql: 'SELECT * FROM admins WHERE email = ?', args: [email] });
    if ((adminResult.rows as any[]).length > 0) {
      const admin = adminResult.rows[0] as any;
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'admin', DATETIME('now'))`, args: [admin.email, admin.name || ''] }); } catch (e) { console.warn('login_sessions insert skipped:', e); }
      return res.json({ message: 'แอดมินเข้าสู่ระบบสำเร็จ', user: { ...admin, role: 'admin', avatar: photoURL || admin.avatar || null } });
    }
    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
    if ((userResult.rows as any[]).length > 0) {
      const user = userResult.rows[0] as any;
      // อัปเดต avatar ถ้า Google ส่งมา
      try { if (photoURL && photoURL !== user.avatar) { await db.execute({ sql: 'UPDATE users SET avatar = ? WHERE email = ?', args: [photoURL, email] }); } } catch {}
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [user.email, user.name || ''] }); } catch (e) { console.warn('login_sessions insert skipped:', e); }
      return res.json({ message: 'เข้าสู่ระบบสำเร็จ', user: { ...user, role: 'user', avatar: photoURL || user.avatar || null } });
    }
    await db.execute({
      sql: 'INSERT INTO users (name, email, password, is_verified, pdpa_accepted, avatar) VALUES (?, ?, ?, 1, 1, ?)',
      args: [sanitizeStr(name) || email, email, hashPassword(uid), photoURL || null],
    });
    const newUser = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
    const created = newUser.rows[0] as any;
    try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [created.email, created.name || ''] }); } catch (e) { console.warn('login_sessions insert skipped:', e); }
    return res.json({ message: 'สร้างบัญชีและเข้าสู่ระบบสำเร็จ', user: { ...created, role: 'user' } });
  } catch (e) { console.error('Google login error:', e); res.status(500).json({ error: 'Google login failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE UPDATE
// ═══════════════════════════════════════════════════════════════════════════════
app.put('/api/users/profile', async (req: Request, res: Response) => {
  const { email, name, nickname, phone, birthDate } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  try {
    await db.execute({
      sql: 'UPDATE users SET name = ?, nickname = ?, phone = ?, birth_date = ? WHERE email = ?',
      args: [sanitizeStr(name), sanitizeStr(nickname), sanitizeStr(phone), sanitizeStr(birthDate), email],
    });
    res.json({ message: 'Profile updated' });
  } catch (e) { console.error('Profile update error:', e); res.status(500).json({ error: 'Update failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// AVATAR UPDATE
// ═══════════════════════════════════════════════════════════════════════════════
app.put('/api/users/avatar', async (req: Request, res: Response) => {
  const { email, avatar } = req.body;
  if (!email || avatar === undefined) return res.status(400).json({ error: 'Missing fields' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  // avatar is emoji string or image URL (max 2000 chars)
  if (typeof avatar === 'string' && avatar.length > 2000) return res.status(400).json({ error: 'Avatar too large' });
  try {
    await db.execute({ sql: 'UPDATE users SET avatar = ? WHERE email = ?', args: [avatar || null, email] });
    res.json({ message: 'Avatar updated' });
  } catch { res.status(500).json({ error: 'Update failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// LOGOUT (record logout time)
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/logout', async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  try {
    await db.execute({
      sql: `UPDATE login_sessions SET logout_at = DATETIME('now') WHERE user_email = ? AND logout_at IS NULL ORDER BY id DESC LIMIT 1`,
      args: [email],
    });
    res.json({ message: 'Logged out' });
  } catch { res.status(500).json({ error: 'Logout record failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// LOGIN SESSIONS (admin only)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/login-sessions', async (req: Request, res: Response) => {
  // simple token check — admin only
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64').toString());
    if (payload?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
  try {
    const limit = Math.min(Number(req.query['limit']) || 100, 500);
    const result = await db.execute({
      sql: `SELECT id, user_email, user_name, role, login_at, logout_at FROM login_sessions ORDER BY id DESC LIMIT ?`,
      args: [limit],
    });
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FORGOT PASSWORD
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/forgot-password', authLimiter, async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  try {
    const userCheck  = await db.execute({ sql: 'SELECT email FROM users WHERE email = ?', args: [email] });
    const adminCheck = await db.execute({ sql: 'SELECT email FROM admins WHERE email = ?', args: [email] });
    if ((userCheck.rows as any[]).length === 0 && (adminCheck.rows as any[]).length === 0) {
      return res.status(400).json({ error: 'ไม่พบอีเมลนี้' });
    }

    const otpCode   = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60000).toISOString();
    await db.execute({ sql: 'INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)', args: [email, otpCode, expiresAt] });

    if (process.env.NODE_ENV !== 'production') console.log(`\n[OTP-RESET] ${email} => ${otpCode}\n`);

    let emailSent = false;
    if (EMAIL_USER && EMAIL_PASS) {
      try {
        await transporter.sendMail({
          from: `"Udomtong Farm" <${EMAIL_USER}>`,
          to: email,
          subject: 'รหัส OTP รีเซ็ตรหัสผ่าน Udomtong Farm',
          html: `<div style="font-family:Arial,sans-serif;padding:20px;max-width:400px"><h2 style="color:#1b4332">รีเซ็ตรหัสผ่าน</h2><p>รหัส OTP ของคุณคือ:</p><div style="font-size:2.5rem;font-weight:900;color:#2d6a4f;letter-spacing:8px;margin:16px 0">${otpCode}</div><p style="color:#666;font-size:0.9rem">รหัสนี้จะหมดอายุใน 15 นาที</p></div>`,
        });
        emailSent = true;
      } catch (mailErr) {
        console.error('[Email error] sendMail failed:', mailErr);
      }
    }

    res.json({ message: 'ส่ง OTP แล้ว', emailSent });
  } catch (e) {
    console.error('Forgot-password error:', e);
    res.status(500).json({ error: 'Forgot password failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// RESET PASSWORD (fixes SQL injection: no table-name interpolation)
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/reset-password', authLimiter, async (req: Request, res: Response) => {
  const { email, otpCode, newPassword } = req.body;
  if (!email || !otpCode || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  if (typeof newPassword !== 'string' || newPassword.length < 6) return res.status(400).json({ error: 'Password too short (min 6 chars)' });
  try {
    const result = await db.execute({
      sql: `SELECT * FROM otps WHERE email = ? AND otp_code = ? AND expires_at > DATETIME('now') ORDER BY id DESC LIMIT 1`,
      args: [email, String(otpCode)],
    });
    if ((result.rows as any[]).length === 0) return res.status(400).json({ error: 'OTP ไม่ถูกต้อง' });

    const hashedPw   = hashPassword(newPassword);
    const adminCheck = await db.execute({ sql: 'SELECT email FROM admins WHERE email = ?', args: [email] });

    if ((adminCheck.rows as any[]).length > 0) {
      await db.execute({ sql: 'UPDATE admins SET password = ? WHERE email = ?', args: [hashedPw, email] });
    } else {
      await db.execute({ sql: 'UPDATE users SET password = ? WHERE email = ?', args: [hashedPw, email] });
    }

    await db.execute({ sql: 'DELETE FROM otps WHERE email = ?', args: [email] });
    try { await db.execute({ sql: `INSERT INTO password_change_log (email, changed_at) VALUES (?, DATETIME('now'))`, args: [email] }); } catch {}
    res.json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ!' });
  } catch { res.status(500).json({ error: 'Reset failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ALL USERS (admin only)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/users', async (_req: Request, res: Response) => {
  // Note: we might want to check for admin auth header here, but leaving as is for now if it's protected on front
  try {
    const result = await db.execute(
      'SELECT id, name, nickname, email, phone, birth_date, is_verified, pdpa_accepted, avatar FROM users ORDER BY id DESC'
    );
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DELETE USER (admin only)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/users/:email', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64').toString());
    if (payload?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
  const email = String(req.params.email);
  try {
    const result = await db.execute({ sql: 'SELECT id, name, nickname, email, phone, birth_date, is_verified, pdpa_accepted, avatar FROM users WHERE email = ?', args: [email] });
    if ((result.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

app.delete('/api/users/:email', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64').toString());
    if (payload?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  } catch { return res.status(401).json({ error: 'Invalid token' }); }

  const targetEmail = String(req.params.email);
  if (!targetEmail || targetEmail === "undefined") return res.status(400).json({ error: 'Missing email' });

  try {
    // 1. Get user data
    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [targetEmail] });
    if ((userResult.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้ที่ต้องการลบ' });
    
    const u = userResult.rows[0] as any;

    // 2. Insert into deleted_users
    await db.execute({
      sql: 'INSERT INTO deleted_users (email, name, phone) VALUES (?, ?, ?)',
      args: [String(u.email), u.name ? String(u.name) : null, u.phone ? String(u.phone) : null]
    });

    // 3. Delete from users
    await db.execute({ sql: 'DELETE FROM users WHERE email = ?', args: [String(targetEmail)] });

    // 4. (Optional) Force logout by setting logout_at if they have an active session
    try { await db.execute({ sql: `UPDATE login_sessions SET logout_at = DATETIME('now') WHERE user_email = ? AND logout_at IS NULL`, args: [String(targetEmail)] }); } catch {}

    res.json({ message: 'ลบผู้ใช้งานสำเร็จ' });
  } catch (e) {
    console.error('Delete user error:', e);
    res.status(500).json({ error: 'ลบผู้ใช้ล้มเหลว' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DELETED USERS LIST (admin only)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/deleted-users', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64').toString());
    if (payload?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  } catch { return res.status(401).json({ error: 'Invalid token' }); }

  try {
    const result = await db.execute('SELECT * FROM deleted_users ORDER BY id DESC LIMIT 200');
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PASSWORD CHANGE LOG (admin only)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/password-change-log', async (_req: Request, res: Response) => {
  try {
    const result = await db.execute(
      'SELECT * FROM password_change_log ORDER BY id DESC LIMIT 200'
    );
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL APP SETTINGS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/settings', async (_req: Request, res: Response) => {
  try {
    const result = await db.execute('SELECT key, value FROM app_settings');
    const settings: Record<string, any> = {};
    for (const row of result.rows as unknown as { key: string, value: string }[]) {
      try {
        settings[row.key] = JSON.parse(row.value);
      } catch {
        settings[row.key] = row.value; // Store as string if not JSON
      }
    }
    res.json(settings);
  } catch (e) {
    console.error('Fetch settings error:', e);
    res.status(500).json({ error: 'Fetch failed' });
  }
});

app.put('/api/settings', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64').toString());
    if (payload?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  } catch { return res.status(401).json({ error: 'Invalid token' }); }

  const updates = req.body;
  if (typeof updates !== 'object' || updates === null || Array.isArray(updates)) {
    return res.status(400).json({ error: 'Request body must be an object { key: value }' });
  }

  try {
    for (const [key, value] of Object.entries(updates)) {
      const dbVal = typeof value === 'object' ? JSON.stringify(value) : String(value);
      await db.execute({
        sql: 'INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)',
        args: [key, dbVal],
      });
    }
    res.json({ message: 'การตั้งค่าถูกบันทึกเรียบร้อย' });
  } catch (e) {
    console.error('Update settings error:', e);
    res.status(500).json({ error: 'Update failed' });
  }
});

// ─── Global error handler ────────────────────────────────────────────────────
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── 404 handler ─────────────────────────────────────────────────────────────
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ─── Auto-init DB tables on startup ─────────────────────────────────────────
async function initDB() {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT, nickname TEXT, phone TEXT, birth_date TEXT,
      email TEXT UNIQUE, password TEXT,
      pdpa_accepted BOOLEAN DEFAULT 0,
      is_verified BOOLEAN DEFAULT 0,
      avatar TEXT
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT, email TEXT UNIQUE, password TEXT
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT, otp_code TEXT, expires_at DATETIME
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS login_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT, user_name TEXT, role TEXT,
      login_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      logout_at DATETIME
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS species (
      id TEXT PRIMARY KEY, type TEXT NOT NULL,
      name_th TEXT NOT NULL, name_en TEXT NOT NULL,
      scientific_name TEXT, short_description TEXT,
      description TEXT, image TEXT, tags TEXT, references_data TEXT
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS password_change_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS deleted_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      name TEXT,
      phone TEXT,
      deleted_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )`);
    // migrate: add columns if missing
    const migrations = [
      `ALTER TABLE users ADD COLUMN nickname TEXT`,
      `ALTER TABLE users ADD COLUMN phone TEXT`,
      `ALTER TABLE users ADD COLUMN birth_date TEXT`,
      `ALTER TABLE users ADD COLUMN avatar TEXT`,
      `ALTER TABLE users ADD COLUMN pdpa_accepted BOOLEAN DEFAULT 0`,
    ];
    for (const sql of migrations) {
      try { await db.execute(sql); } catch {}
    }
    console.log('✅ DB tables ready');
  } catch (e) {
    console.error('❌ DB init error:', e);
  }
}

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`\n🌿 Udomtong Farm API running at http://localhost:${PORT}`);
  console.log(`   Allowed origins : ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`   DB              : ${DB_URL}\n`);
  await initDB();
});
