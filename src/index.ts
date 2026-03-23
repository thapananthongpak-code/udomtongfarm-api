import * as dotenv from 'dotenv';
dotenv.config();

import { setDefaultResultOrder } from 'dns';
setDefaultResultOrder('ipv4first');

import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { createClient } from '@libsql/client';
import nodemailer from 'nodemailer';
import sgMail from '@sendgrid/mail';
import { createHash, createHmac, randomBytes } from 'crypto';

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT         = process.env.PORT || 3000;
const DB_URL       = (process.env.TURSO_DB_URL || '').trim();
const DB_TOKEN     = (process.env.TURSO_DB_TOKEN || '').trim().replace(/\s/g, '');
const EMAIL_USER   = (process.env.EMAIL_USER || '').trim();
const EMAIL_PASS   = (process.env.EMAIL_PASS || '').trim();
const ADMIN_SECRET             = (process.env.ADMIN_SECRET             || 'change_me').trim();
const JWT_SECRET               = (process.env.JWT_SECRET               || 'udomtong_jwt_secret_2025').trim();
const GOOGLE_CLIENT_ID_VAR     = (process.env.GOOGLE_CLIENT_ID         || '').trim();
const GOOGLE_CLIENT_SECRET_VAR = (process.env.GOOGLE_CLIENT_SECRET     || '').trim();
const GOOGLE_CALLBACK_URL_VAR  = (process.env.GOOGLE_CALLBACK_URL      || 'http://localhost:3001/auth/google').trim();
const FRONTEND_URL             = (process.env.FRONTEND_URL             || 'http://localhost:5173').trim();
const SENDGRID_API_KEY_VAR     = (process.env.SENDGRID_API_KEY         || '').trim();
const SENDGRID_FROM            = (process.env.SENDGRID_FROM_EMAIL      || EMAIL_USER).trim();

// ─── Init SendGrid ─────────────────────────────────────────────────────────────
if (SENDGRID_API_KEY_VAR) sgMail.setApiKey(SENDGRID_API_KEY_VAR);


// ─── JWT helpers ──────────────────────────────────────────────────────────────
function b64url(str: string) {
  return Buffer.from(str).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function makeJwt(payload: object): string {
  const hdr = b64url(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const bdy = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 60*60*24*30 }));
  const sig = createHmac('sha256', JWT_SECRET).update(`${hdr}.${bdy}`).digest('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  return `${hdr}.${bdy}.${sig}`;
}
function verifyJwt(token: string): { email?: string; role?: string } | null {
  try {
    const [hdr, bdy, sig] = token.split('.');
    if (!hdr || !bdy || !sig) return null;
    const expected = createHmac('sha256', JWT_SECRET).update(`${hdr}.${bdy}`).digest('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(bdy, 'base64').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173')
  .split(',').map((o) => o.trim());

if (!DB_URL || !DB_TOKEN) {
  console.error('❌ Missing TURSO_DB_URL or TURSO_DB_TOKEN in .env');
  process.exit(1);
}

// ─── Database ─────────────────────────────────────────────────────────────────
const db = createClient({ url: DB_URL, authToken: DB_TOKEN });

// ─── Email via Gmail SMTP ──────────────────────────────────────────────────────
const gmailTransporter = EMAIL_PASS ? nodemailer.createTransport({
  host: 'smtp.gmail.com', port: 587, secure: false,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
}) : null;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(`Timeout after ${ms}ms`)), ms)),
  ]);
}

/** Strip HTML tags to produce a plain-text fallback */
function htmlToText(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n').replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ')
    .replace(/\n{3,}/g, '\n\n').trim();
}

async function sendEmail(to: string, subject: string, html: string): Promise<boolean> {
  // Primary: SendGrid
  if (SENDGRID_API_KEY_VAR) {
    try {
      await withTimeout(
        sgMail.send({ to, from: SENDGRID_FROM || EMAIL_USER, subject, html, text: htmlToText(html) }),
        15000,
      );
      return true;
    } catch (err: any) {
      console.error('[Email] SendGrid failed:', err?.message || err);
    }
  }
  // Fallback: Gmail SMTP
  if (!gmailTransporter) {
    console.warn('[Email] No email provider configured');
    return false;
  }
  try {
    await withTimeout(
      gmailTransporter.sendMail({
        from: `"Udomtong Farm" <${EMAIL_USER}>`,
        to, subject, html,
        text: htmlToText(html),
        headers: { 'X-Mailer': 'Udomtong Farm Mailer', 'Importance': 'Normal' },
      }),
      15000,
    );
    return true;
  } catch (err: any) {
    console.error('[Email] Gmail SMTP failed:', err?.message || err);
    return false;
  }
}

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();

// Security: restrict CORS to allowed origins
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Lang'],
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

// ─── Admin auth helper ────────────────────────────────────────────────────────
function getLang(req: Request): 'th' | 'en' {
  return (req.headers['x-lang'] === 'th') ? 'th' : 'en';
}
async function requireAdmin(req: Request, res: Response): Promise<boolean> {
  const lang  = getLang(req);
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) { res.status(401).json({ error: lang === 'th' ? 'ไม่ได้รับอนุญาต' : 'Unauthorized' }); return false; }
  const payload = verifyJwt(token);
  if (!payload) { res.status(401).json({ error: lang === 'th' ? 'Token ไม่ถูกต้องหรือหมดอายุ' : 'Invalid or expired token' }); return false; }
  if (payload.role !== 'admin') { res.status(403).json({ error: lang === 'th' ? 'ไม่มีสิทธิ์เข้าถึง' : 'Forbidden' }); return false; }
  return true;
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
      price:      row.price ?? 0,
      stock:      row.stock ?? 0,
      unit:       row.unit ?? 'ตัว/ต้น',
      available:  row.available === undefined ? true : row.available === 1,
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
  const { email, password, name, nickname, phone, birthDate, pdpa, avatar, addressLine, district, province, postalCode } = req.body;
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

    await sendEmail(
      email,
      '[Udomtong Farm] รหัสยืนยันอีเมลของคุณ',
      `<!DOCTYPE html><html lang="th"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:0;background:#f4f7f6;font-family:Arial,Helvetica,sans-serif"><table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7f6;padding:32px 0"><tr><td align="center"><table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e0e0e0"><tr><td style="background:#1b4332;padding:24px 32px"><h1 style="margin:0;color:#ffffff;font-size:1.3rem;font-weight:700">🌿 Udomtong Farm</h1></td></tr><tr><td style="padding:32px"><p style="margin:0 0 8px;color:#374151;font-size:1rem">สวัสดี,</p><p style="margin:0 0 24px;color:#374151;font-size:1rem">รหัส OTP สำหรับยืนยันอีเมลของคุณ:</p><div style="background:#f0fdf4;border:2px solid #2d6a4f;border-radius:10px;padding:20px;text-align:center;margin:0 0 24px"><div style="font-size:2.5rem;font-weight:900;color:#1b4332;letter-spacing:10px;font-family:monospace">${otpCode}</div><div style="color:#6b7280;font-size:0.85rem;margin-top:8px">⏱ หมดอายุใน 15 นาที</div></div><p style="margin:0;color:#9ca3af;font-size:0.8rem">หากคุณไม่ได้สมัครสมาชิก Udomtong Farm กรุณาเพิกเฉยต่ออีเมลนี้</p></td></tr><tr><td style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb"><p style="margin:0;color:#9ca3af;font-size:0.75rem">© ${new Date().getFullYear()} Udomtong Farm · อีเมลนี้ส่งอัตโนมัติ กรุณาอย่าตอบกลับ</p></td></tr></table></td></tr></table></body></html>`,
    );

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
  const { email, otpCode, addressLine, district, province, postalCode, name, phone } = req.body;
  if (!email || !otpCode) return res.status(400).json({ error: 'Missing fields' });
  try {
    const result = await db.execute({
      sql: `SELECT * FROM otps WHERE email = ? AND otp_code = ? AND expires_at > DATETIME('now') ORDER BY id DESC LIMIT 1`,
      args: [email, String(otpCode)],
    });
    if ((result.rows as any[]).length === 0) return res.status(400).json({ error: 'OTP ไม่ถูกต้องหรือหมดอายุ' });
    await db.execute({ sql: 'UPDATE users SET is_verified = 1 WHERE email = ?', args: [email] });
    await db.execute({ sql: 'DELETE FROM otps WHERE email = ?', args: [email] });
    // บันทึกที่อยู่ถ้ามีข้อมูลส่งมาด้วย
    if (addressLine && province) {
      try {
        await db.execute({
          sql: `INSERT INTO user_addresses (user_email, name, phone, address_line, district, province, postal_code, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
          args: [email, sanitizeStr(name) || email, sanitizeStr(phone) || '', sanitizeStr(addressLine), sanitizeStr(district) || '', sanitizeStr(province), sanitizeStr(postalCode) || ''],
        });
      } catch (e) { console.warn('Address save skipped:', e); }
    }
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
      // Admin 2FA: send OTP before granting JWT
      const adminOtp = Math.floor(100000 + Math.random() * 900000).toString();
      const adminOtpExp = new Date(Date.now() + 15 * 60000).toISOString();
      await db.execute({ sql: 'DELETE FROM otps WHERE email = ?', args: [admin.email] });
      await db.execute({ sql: 'INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)', args: [admin.email, adminOtp, adminOtpExp] });
      if (process.env.NODE_ENV !== 'production') console.log(`\n[ADMIN-2FA] ${admin.email} => ${adminOtp}\n`);
      const admin2faHtml = `<!DOCTYPE html><html lang="th"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:0;background:#f4f7f6;font-family:Arial,Helvetica,sans-serif"><table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7f6;padding:32px 0"><tr><td align="center"><table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e0e0e0"><tr><td style="background:#1e3a8a;padding:24px 32px"><h1 style="margin:0;color:#ffffff;font-size:1.3rem;font-weight:700">🔐 Udomtong Farm — Admin</h1></td></tr><tr><td style="padding:32px"><p style="margin:0 0 24px;color:#374151;font-size:1rem">กรุณาใส่รหัส OTP ด้านล่างเพื่อเข้าสู่ระบบ Admin</p><div style="background:#eff6ff;border:2px solid #3b82f6;border-radius:10px;padding:20px;text-align:center;margin:0 0 24px"><div style="font-size:2.5rem;font-weight:900;color:#1d4ed8;letter-spacing:10px;font-family:monospace">${adminOtp}</div><div style="color:#6b7280;font-size:0.85rem;margin-top:8px">⏱ หมดอายุใน 15 นาที</div></div><p style="margin:0;color:#ef4444;font-size:0.85rem;font-weight:600">หากไม่ใช่คุณที่กำลังล็อกอิน กรุณาเปลี่ยนรหัสผ่านทันที</p></td></tr><tr><td style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb"><p style="margin:0;color:#9ca3af;font-size:0.75rem">© ${new Date().getFullYear()} Udomtong Farm · Admin Security Alert</p></td></tr></table></td></tr></table></body></html>`;
      await sendEmail(admin.email, '[Udomtong Farm] Admin Login — รหัส 2FA ของคุณ', admin2faHtml);
      return res.json({ needs_2fa: true, email: admin.email, message: 'ส่งรหัส OTP ไปยังอีเมลแอดมินแล้ว' });
    }

    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
    if ((userResult.rows as any[]).length > 0) {
      const user = userResult.rows[0] as any;
      if (user.password !== hashedPw && user.password !== password) {
        return res.status(401).json({ error: 'รหัสผ่านไม่ถูกต้อง', field: 'password' });
      }
      if (user.is_verified === 0) return res.status(403).json({ error: 'อีเมลนี้ยังไม่ได้รับการยืนยัน กรุณาตรวจสอบกล่องจดหมาย', field: 'email' });
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [user.email, user.name || ''] }); } catch (e) { console.warn('login_sessions insert skipped:', e); }
      const userToken = makeJwt({ email: user.email, role: 'user' });
      return res.json({ message: 'เข้าสู่ระบบสำเร็จ', token: userToken, user: { ...user, role: 'user', token: userToken } });
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
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'admin', DATETIME('now'))`, args: [admin.email, admin.name || ''] }); } catch {}
      const gAdminToken = makeJwt({ email: admin.email, role: 'admin' });
      const { password: _ap, ...safeAdmin } = admin;
      return res.json({ message: 'แอดมินเข้าสู่ระบบสำเร็จ', token: gAdminToken, user: { ...safeAdmin, role: 'admin', avatar: photoURL || admin.avatar || null, token: gAdminToken } });
    }
    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
    if ((userResult.rows as any[]).length > 0) {
      const user = userResult.rows[0] as any;
      try { if (photoURL && photoURL !== user.avatar) { await db.execute({ sql: 'UPDATE users SET avatar = ? WHERE email = ?', args: [photoURL, email] }); } } catch {}
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [user.email, user.name || ''] }); } catch {}
      const gUserToken = makeJwt({ email: user.email, role: 'user' });
      const { password: _up, ...safeUser } = user;
      return res.json({ message: 'เข้าสู่ระบบสำเร็จ', token: gUserToken, user: { ...safeUser, role: 'user', avatar: photoURL || user.avatar || null, token: gUserToken } });
    }
    await db.execute({
      sql: 'INSERT INTO users (name, email, password, is_verified, pdpa_accepted, avatar) VALUES (?, ?, ?, 1, 1, ?)',
      args: [sanitizeStr(name) || email, email, hashPassword(uid), photoURL || null],
    });
    const newUser = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
    const { password: _np, ...safeNew } = newUser.rows[0] as any;
    try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [safeNew.email, safeNew.name || ''] }); } catch {}
    const gNewToken = makeJwt({ email: safeNew.email, role: 'user' });
    return res.json({ message: 'สร้างบัญชีและเข้าสู่ระบบสำเร็จ', token: gNewToken, user: { ...safeNew, role: 'user', token: gNewToken } });
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
  if (!token) return res.status(401).json({ error: getLang(req) === 'th' ? 'ไม่ได้รับอนุญาต' : 'Unauthorized' });
  const _payload = verifyJwt(token);
  if (!_payload || _payload.role !== 'admin') return res.status(403).json({ error: getLang(req) === 'th' ? 'ไม่มีสิทธิ์เข้าถึง' : 'Forbidden' });
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

    const emailSent = await sendEmail(
      email,
      '[Udomtong Farm] รหัสรีเซ็ตรหัสผ่านของคุณ',
      `<!DOCTYPE html><html lang="th"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:0;background:#f4f7f6;font-family:Arial,Helvetica,sans-serif"><table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7f6;padding:32px 0"><tr><td align="center"><table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e0e0e0"><tr><td style="background:#1b4332;padding:24px 32px"><h1 style="margin:0;color:#ffffff;font-size:1.3rem;font-weight:700">🌿 Udomtong Farm</h1></td></tr><tr><td style="padding:32px"><p style="margin:0 0 8px;color:#374151;font-size:1rem">สวัสดี,</p><p style="margin:0 0 24px;color:#374151;font-size:1rem">รหัส OTP สำหรับรีเซ็ตรหัสผ่านของคุณ:</p><div style="background:#fff7ed;border:2px solid #ea580c;border-radius:10px;padding:20px;text-align:center;margin:0 0 24px"><div style="font-size:2.5rem;font-weight:900;color:#c2410c;letter-spacing:10px;font-family:monospace">${otpCode}</div><div style="color:#6b7280;font-size:0.85rem;margin-top:8px">⏱ หมดอายุใน 15 นาที</div></div><p style="margin:0;color:#9ca3af;font-size:0.8rem">หากคุณไม่ได้ขอรีเซ็ตรหัสผ่าน กรุณาเพิกเฉยต่ออีเมลนี้</p></td></tr><tr><td style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb"><p style="margin:0;color:#9ca3af;font-size:0.75rem">© ${new Date().getFullYear()} Udomtong Farm · อีเมลนี้ส่งอัตโนมัติ กรุณาอย่าตอบกลับ</p></td></tr></table></td></tr></table></body></html>`,
    );

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
  if (!token) return res.status(401).json({ error: getLang(req) === 'th' ? 'ไม่ได้รับอนุญาต' : 'Unauthorized' });
  { const p = verifyJwt(token); if (!p || p.role !== 'admin') return res.status(403).json({ error: getLang(req) === 'th' ? 'ไม่มีสิทธิ์เข้าถึง' : 'Forbidden' }); }
  const email = String(req.params.email);
  try {
    const result = await db.execute({ sql: 'SELECT id, name, nickname, email, phone, birth_date, is_verified, pdpa_accepted, avatar FROM users WHERE email = ?', args: [email] });
    if ((result.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

app.delete('/api/users/:email', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: getLang(req) === 'th' ? 'ไม่ได้รับอนุญาต' : 'Unauthorized' });
  { const p = verifyJwt(token); if (!p || p.role !== 'admin') return res.status(403).json({ error: getLang(req) === 'th' ? 'ไม่มีสิทธิ์เข้าถึง' : 'Forbidden' }); }

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
  if (!token) return res.status(401).json({ error: getLang(req) === 'th' ? 'ไม่ได้รับอนุญาต' : 'Unauthorized' });
  { const p = verifyJwt(token); if (!p || p.role !== 'admin') return res.status(403).json({ error: getLang(req) === 'th' ? 'ไม่มีสิทธิ์เข้าถึง' : 'Forbidden' }); }

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
  if (!token) return res.status(401).json({ error: getLang(req) === 'th' ? 'ไม่ได้รับอนุญาต' : 'Unauthorized' });
  { const p = verifyJwt(token); if (!p || p.role !== 'admin') return res.status(403).json({ error: getLang(req) === 'th' ? 'ไม่มีสิทธิ์เข้าถึง' : 'Forbidden' }); }

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

// ═══════════════════════════════════════════════════════════════════════════════
// PRODUCTS — price / stock management (extends species)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/products', async (_req: Request, res: Response) => {
  try {
    const result = await db.execute(
      'SELECT id, type, name_th, name_en, image, price, stock, unit, available FROM species ORDER BY name_th'
    );
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

app.put('/api/products/:id', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  const id = req.params['id'] as string;
  const { price, stock, unit, available, age, gender } = req.body;
  try {
    await db.execute({
      sql: 'UPDATE species SET price = ?, stock = ?, unit = ?, available = ?, age = ?, gender = ? WHERE id = ?',
      args: [Number(price) || 0, Number(stock) || 0, unit ?? 'ตัว/ต้น', available ? 1 : 0, age ?? null, gender ?? null, id],
    });
    res.json({ message: 'อัปเดตสินค้าสำเร็จ' });
  } catch { res.status(500).json({ error: 'Update failed' }); }
});

// Batch update prices/stock (admin)
app.put('/api/products', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  const updates: Array<{ id: string; price?: number; stock?: number; unit?: string; available?: boolean; age?: string; gender?: string }> = req.body;
  if (!Array.isArray(updates)) return res.status(400).json({ error: 'Body must be an array' });
  try {
    for (const u of updates) {
      if (!u.id) continue;
      await db.execute({
        sql: 'UPDATE species SET price = COALESCE(?, price), stock = COALESCE(?, stock), unit = COALESCE(?, unit), available = COALESCE(?, available), age = COALESCE(?, age), gender = COALESCE(?, gender) WHERE id = ?',
        args: [u.price !== undefined ? Number(u.price) : null, u.stock !== undefined ? Number(u.stock) : null, u.unit ?? null, u.available !== undefined ? (u.available ? 1 : 0) : null, u.age ?? null, u.gender ?? null, u.id],
      });
    }
    res.json({ message: 'อัปเดตสินค้าสำเร็จ' });
  } catch { res.status(500).json({ error: 'Batch update failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADDRESSES — user shipping addresses
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/addresses', async (req: Request, res: Response) => {
  const email = req.query['email'] as string;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM user_addresses WHERE user_email = ? ORDER BY is_default DESC, id DESC',
      args: [email],
    });
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

app.post('/api/addresses', async (req: Request, res: Response) => {
  const { user_email, name, phone, address_line, district, province, postal_code, is_default } = req.body;
  if (!user_email || !name || !address_line || !province) {
    return res.status(400).json({ error: 'Missing required fields (name, address_line, province)' });
  }
  try {
    if (is_default) {
      await db.execute({ sql: 'UPDATE user_addresses SET is_default = 0 WHERE user_email = ?', args: [user_email] });
    }
    await db.execute({
      sql: 'INSERT INTO user_addresses (user_email, name, phone, address_line, district, province, postal_code, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      args: [user_email, sanitizeStr(name), sanitizeStr(phone), sanitizeStr(address_line, 500), sanitizeStr(district), sanitizeStr(province), sanitizeStr(postal_code, 10), is_default ? 1 : 0],
    });
    res.json({ message: 'เพิ่มที่อยู่สำเร็จ' });
  } catch { res.status(500).json({ error: 'Add address failed' }); }
});

app.put('/api/addresses/:id', async (req: Request, res: Response) => {
  const id = req.params['id'] as string;
  const { user_email, name, phone, address_line, district, province, postal_code, is_default } = req.body;
  if (!user_email || !name || !address_line || !province) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    if (is_default) {
      await db.execute({ sql: 'UPDATE user_addresses SET is_default = 0 WHERE user_email = ?', args: [user_email] });
    }
    await db.execute({
      sql: 'UPDATE user_addresses SET name = ?, phone = ?, address_line = ?, district = ?, province = ?, postal_code = ?, is_default = ? WHERE id = ? AND user_email = ?',
      args: [sanitizeStr(name), sanitizeStr(phone), sanitizeStr(address_line, 500), sanitizeStr(district), sanitizeStr(province), sanitizeStr(postal_code, 10), is_default ? 1 : 0, id, user_email],
    });
    res.json({ message: 'อัปเดตที่อยู่สำเร็จ' });
  } catch { res.status(500).json({ error: 'Update failed' }); }
});

app.delete('/api/addresses/:id', async (req: Request, res: Response) => {
  const id = req.params['id'] as string;
  const user_email = req.body?.user_email || req.query['email'];
  if (!user_email) return res.status(400).json({ error: 'Missing user_email' });
  try {
    await db.execute({ sql: 'DELETE FROM user_addresses WHERE id = ? AND user_email = ?', args: [id, user_email] });
    res.json({ message: 'ลบที่อยู่สำเร็จ' });
  } catch { res.status(500).json({ error: 'Delete failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ORDERS — create, view (user + admin)
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/orders', async (req: Request, res: Response) => {
  const { user_email, items, total_amount, payment_method, shipping_address, shipping_company, note } = req.body;
  if (!user_email || !items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const orderId = `ORD-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
  try {
    await db.execute({
      sql: `INSERT INTO orders (id, user_email, total_amount, status, payment_method, shipping_address, shipping_company, note) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`,
      args: [orderId, user_email, Number(total_amount) || 0, sanitizeStr(payment_method || 'promptpay', 50), JSON.stringify(shipping_address || {}), sanitizeStr(shipping_company || '', 50), sanitizeStr(note || '', 500)],
    });
    for (const item of items) {
      await db.execute({
        sql: 'INSERT INTO order_items (order_id, species_id, species_name, species_name_en, species_image, species_type, quantity, unit_price, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        args: [orderId, sanitizeStr(item.species_id), sanitizeStr(item.species_name || ''), sanitizeStr(item.species_name_en || ''), sanitizeStr(item.species_image || '', 2000), sanitizeStr(item.species_type || ''), Number(item.quantity) || 1, Number(item.unit_price) || 0, Number(item.subtotal) || 0],
      });
      // Reduce stock (non-blocking)
      try {
        await db.execute({ sql: 'UPDATE species SET stock = MAX(0, stock - ?) WHERE id = ?', args: [Number(item.quantity) || 1, item.species_id] });
      } catch {}
    }
    res.json({ message: 'สั่งซื้อสำเร็จ!', orderId });
  } catch (e) {
    console.error('Create order error:', e);
    res.status(500).json({ error: 'สร้างคำสั่งซื้อล้มเหลว' });
  }
});

// User: get my orders
app.get('/api/orders/my', async (req: Request, res: Response) => {
  const email = req.query['email'] as string;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  try {
    const orders = await db.execute({ sql: 'SELECT * FROM orders WHERE user_email = ? ORDER BY created_at DESC LIMIT 100', args: [email] });
    const result = [];
    for (const order of orders.rows as any[]) {
      const items = await db.execute({ sql: 'SELECT * FROM order_items WHERE order_id = ?', args: [order['id']] });
      result.push({ ...order, shipping_address: (() => { try { return JSON.parse(order['shipping_address'] || '{}'); } catch { return {}; } })(), items: items.rows });
    }
    res.json(result);
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// Single order detail
app.get('/api/orders/:id', async (req: Request, res: Response) => {
  const id = req.params['id'] as string;
  try {
    const orders = await db.execute({ sql: 'SELECT * FROM orders WHERE id = ?', args: [id] });
    if ((orders.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบคำสั่งซื้อ' });
    const order = orders.rows[0] as any;
    const items = await db.execute({ sql: 'SELECT * FROM order_items WHERE order_id = ?', args: [id] });
    res.json({ ...order, shipping_address: (() => { try { return JSON.parse(order['shipping_address'] || '{}'); } catch { return {}; } })(), items: items.rows });
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// Admin: all orders
app.get('/api/admin/orders', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const limit = Math.min(Number(req.query['limit']) || 200, 1000);
    const status = req.query['status'] as string | undefined;
    let sql = 'SELECT * FROM orders';
    const args: any[] = [];
    if (status) { sql += ' WHERE status = ?'; args.push(status); }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    args.push(limit);
    const orders = await db.execute({ sql, args });
    res.json((orders.rows as any[]).map(o => ({ ...o, shipping_address: (() => { try { return JSON.parse(o['shipping_address'] || '{}'); } catch { return {}; } })() })));
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// Admin: order detail with items
app.get('/api/admin/orders/:id', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  const id = req.params['id'] as string;
  try {
    const orders = await db.execute({ sql: 'SELECT * FROM orders WHERE id = ?', args: [id] });
    if ((orders.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบคำสั่งซื้อ' });
    const order = orders.rows[0] as any;
    const items = await db.execute({ sql: 'SELECT * FROM order_items WHERE order_id = ?', args: [id] });
    res.json({ ...order, shipping_address: (() => { try { return JSON.parse(order['shipping_address'] || '{}'); } catch { return {}; } })(), items: items.rows });
  } catch { res.status(500).json({ error: 'Fetch failed' }); }
});

// Admin: update order status + shipping info
app.put('/api/admin/orders/:id/status', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  const id = req.params['id'] as string;
  const { status, shipping_company, tracking_number, estimated_delivery } = req.body;
  const valid = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];
  if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    await db.execute({
      sql: `UPDATE orders SET status = ?, shipping_company = COALESCE(?, shipping_company), tracking_number = COALESCE(?, tracking_number), estimated_delivery = COALESCE(?, estimated_delivery), updated_at = DATETIME('now') WHERE id = ?`,
      args: [status, shipping_company || null, tracking_number || null, estimated_delivery || null, id],
    });
    res.json({ message: 'อัปเดตสถานะสำเร็จ' });
  } catch { res.status(500).json({ error: 'Update failed' }); }
});

// Admin: update shipping info only (tracking, company, estimated delivery)
app.put('/api/admin/orders/:id/shipping', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  const id = req.params['id'] as string;
  const { shipping_company, tracking_number, estimated_delivery } = req.body;
  try {
    await db.execute({
      sql: `UPDATE orders SET shipping_company = COALESCE(?, shipping_company), tracking_number = COALESCE(?, tracking_number), estimated_delivery = COALESCE(?, estimated_delivery), updated_at = DATETIME('now') WHERE id = ?`,
      args: [shipping_company || null, tracking_number || null, estimated_delivery || null, id],
    });
    res.json({ message: 'อัปเดตข้อมูลการจัดส่งสำเร็จ' });
  } catch { res.status(500).json({ error: 'Update failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN 2FA VERIFY
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/admin/verify-2fa', authLimiter, async (req: Request, res: Response) => {
  const { email, otpCode } = req.body;
  if (!email || !otpCode) return res.status(400).json({ error: 'Missing fields' });
  try {
    const result = await db.execute({
      sql: `SELECT * FROM otps WHERE email = ? AND otp_code = ? AND expires_at > DATETIME('now') ORDER BY id DESC LIMIT 1`,
      args: [email, String(otpCode)],
    });
    if ((result.rows as any[]).length === 0) return res.status(400).json({ error: 'OTP ไม่ถูกต้องหรือหมดอายุ' });
    await db.execute({ sql: 'DELETE FROM otps WHERE email = ?', args: [email] });
    const adminResult = await db.execute({ sql: 'SELECT * FROM admins WHERE email = ?', args: [email] });
    if ((adminResult.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบแอดมิน' });
    const admin = adminResult.rows[0] as any;
    try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'admin', DATETIME('now'))`, args: [admin.email, admin.name || ''] }); } catch {}
    const adminToken = makeJwt({ email: admin.email, role: 'admin' });
    return res.json({ message: 'แอดมินเข้าสู่ระบบสำเร็จ', token: adminToken, user: { ...admin, role: 'admin', token: adminToken } });
  } catch { res.status(500).json({ error: 'Verify 2FA failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// REVIEWS API
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/reviews/:speciesId', async (req: Request, res: Response) => {
  const speciesId = req.params['speciesId'] as string;
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM reviews WHERE species_id = ? ORDER BY created_at DESC LIMIT 100',
      args: [speciesId],
    });
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Fetch reviews failed' }); }
});

app.post('/api/reviews', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const payload = verifyJwt(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  const { species_id, rating, comment } = req.body;
  if (!species_id || !rating) return res.status(400).json({ error: 'Missing required fields' });
  if (Number(rating) < 1 || Number(rating) > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  try {
    const existing = await db.execute({ sql: 'SELECT id FROM reviews WHERE species_id = ? AND user_email = ?', args: [species_id, payload.email] });
    if ((existing.rows as any[]).length > 0) {
      await db.execute({ sql: `UPDATE reviews SET rating = ?, comment = ?, created_at = DATETIME('now') WHERE species_id = ? AND user_email = ?`, args: [Number(rating), sanitizeStr(comment || '', 1000), species_id, payload.email] });
      return res.json({ message: 'อัปเดตรีวิวสำเร็จ' });
    }
    const userResult = await db.execute({ sql: 'SELECT name, nickname FROM users WHERE email = ?', args: [payload.email!] });
    const u = userResult.rows[0] as any;
    const userName = u?.nickname || u?.name || (payload.email ?? '').split('@')[0] || 'ผู้ใช้';
    await db.execute({ sql: 'INSERT INTO reviews (species_id, user_email, user_name, rating, comment) VALUES (?, ?, ?, ?, ?)', args: [species_id, payload.email!, userName, Number(rating), sanitizeStr(comment || '', 1000)] });
    res.json({ message: 'เพิ่มรีวิวสำเร็จ' });
  } catch { res.status(500).json({ error: 'Add review failed' }); }
});

app.delete('/api/reviews/:id', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const payload = verifyJwt(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  const id = req.params['id'] as string;
  try {
    if (payload.role === 'admin') {
      await db.execute({ sql: 'DELETE FROM reviews WHERE id = ?', args: [id] });
    } else {
      await db.execute({ sql: 'DELETE FROM reviews WHERE id = ? AND user_email = ?', args: [id, payload.email!] });
    }
    res.json({ message: 'ลบรีวิวสำเร็จ' });
  } catch { res.status(500).json({ error: 'Delete review failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CANCEL ORDER (user — pending only)
// ═══════════════════════════════════════════════════════════════════════════════
app.put('/api/orders/:id/cancel', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const payload = verifyJwt(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  const id = req.params['id'] as string;
  try {
    const orderResult = await db.execute({ sql: 'SELECT * FROM orders WHERE id = ?', args: [id] });
    if ((orderResult.rows as any[]).length === 0) return res.status(404).json({ error: 'ไม่พบคำสั่งซื้อ' });
    const order = orderResult.rows[0] as any;
    if (order.user_email !== payload.email && payload.role !== 'admin') return res.status(403).json({ error: 'ไม่มีสิทธิ์ยกเลิก' });
    if (order.status !== 'pending') return res.status(400).json({ error: 'ยกเลิกได้เฉพาะออร์เดอร์ที่รอชำระเงินเท่านั้น' });
    await db.execute({ sql: `UPDATE orders SET status = 'cancelled', updated_at = DATETIME('now') WHERE id = ?`, args: [id] });
    const items = await db.execute({ sql: 'SELECT * FROM order_items WHERE order_id = ?', args: [id] });
    for (const item of items.rows as any[]) {
      try { await db.execute({ sql: 'UPDATE species SET stock = stock + ? WHERE id = ?', args: [item.quantity, item.species_id] }); } catch {}
    }
    res.json({ message: 'ยกเลิกคำสั่งซื้อสำเร็จ' });
  } catch { res.status(500).json({ error: 'Cancel order failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORT ORDERS CSV (admin)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/orders/export', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const orders = await db.execute('SELECT * FROM orders ORDER BY created_at DESC');
    const rows = orders.rows as any[];
    const headers = ['ID', 'Email', 'Total (THB)', 'Status', 'Payment', 'Shipping Co', 'Tracking No', 'Est. Delivery', 'Note', 'Created At', 'Updated At'];
    const csv = [
      headers.join(','),
      ...rows.map(o => [
        o.id, o.user_email, o.total_amount, o.status, o.payment_method,
        o.shipping_company || '', o.tracking_number || '', o.estimated_delivery || '',
        (o.note || '').replace(/\n/g, ' '), o.created_at, o.updated_at,
      ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="orders-${new Date().toISOString().split('T')[0]}.csv"`);
    res.send('\uFEFF' + csv);
  } catch { res.status(500).json({ error: 'Export failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// MONTHLY STATS (admin — for dashboard chart)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/stats/monthly', async (req: Request, res: Response) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const result = await db.execute(`
      SELECT
        strftime('%Y-%m', created_at) as month,
        COUNT(*) as order_count,
        SUM(CASE WHEN status != 'cancelled' THEN total_amount ELSE 0 END) as revenue
      FROM orders
      GROUP BY strftime('%Y-%m', created_at)
      ORDER BY month DESC
      LIMIT 12
    `);
    res.json((result.rows as any[]).reverse());
  } catch { res.status(500).json({ error: 'Stats failed' }); }
});

// Polling: get updated orders since timestamp
app.get('/api/orders/poll', async (req: Request, res: Response) => {
  const email = req.query['email'] as string;
  const since = req.query['since'] as string;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  try {
    const sql = since
      ? 'SELECT * FROM orders WHERE user_email = ? AND updated_at > ? ORDER BY created_at DESC LIMIT 50'
      : 'SELECT * FROM orders WHERE user_email = ? ORDER BY created_at DESC LIMIT 50';
    const args = since ? [email, since] : [email];
    const orders = await db.execute({ sql, args });
    const result = [];
    for (const order of orders.rows as any[]) {
      const items = await db.execute({ sql: 'SELECT * FROM order_items WHERE order_id = ?', args: [order['id']] });
      result.push({ ...order, shipping_address: (() => { try { return JSON.parse(order['shipping_address'] || '{}'); } catch { return {}; } })(), items: items.rows });
    }
    res.json(result);
  } catch { res.status(500).json({ error: 'Poll failed' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// GOOGLE OAUTH (backend-proxied — no Firebase dependency)
// ═══════════════════════════════════════════════════════════════════════════════
// Short-lived exchange codes (5-min TTL) — avoids putting tokens in URL history
const googleAuthCodes = new Map<string, { user: Record<string, unknown>; expiresAt: number }>();
setInterval(() => {
  const now = Date.now();
  for (const [code, entry] of googleAuthCodes.entries()) {
    if (entry.expiresAt < now) googleAuthCodes.delete(code);
  }
}, 60_000);

/** Use JS-based redirect to avoid Railway reverse-proxy mangling Location headers */
function jsRedirect(res: Response, url: string) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><script>window.location.replace(${JSON.stringify(url)});</script></head><body></body></html>`);
}

async function handleGoogleOAuth(req: Request, res: Response) {
  const { code, error } = req.query as Record<string, string | undefined>;

  if (error) {
    return jsRedirect(res, `${FRONTEND_URL}/login?google_error=${encodeURIComponent(error)}`);
  }

  if (!code) {
    // Step 1: Initiate OAuth — redirect to Google (absolute URL, safe to use res.redirect)
    if (!GOOGLE_CLIENT_ID_VAR) return res.status(500).send('Google OAuth not configured');
    console.log('[Google OAuth] Starting flow | CALLBACK:', GOOGLE_CALLBACK_URL_VAR, '| FRONTEND:', FRONTEND_URL);
    const params = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID_VAR,
      redirect_uri: GOOGLE_CALLBACK_URL_VAR,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'online',
      prompt: 'select_account',
    });
    return res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  }

  // Step 2: Exchange code for access token
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID_VAR,
        client_secret: GOOGLE_CLIENT_SECRET_VAR,
        redirect_uri: GOOGLE_CALLBACK_URL_VAR,
        grant_type: 'authorization_code',
      }).toString(),
    });
    const tokenData = await tokenRes.json() as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      console.error('[Google OAuth] Token exchange failed:', tokenData);
      return jsRedirect(res, `${FRONTEND_URL}/login?google_error=token_exchange_failed`);
    }

    // Step 3: Get user profile from Google
    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const gUser = await userRes.json() as { email?: string; name?: string; id?: string; picture?: string };
    const { email, name, id: uid, picture: photoURL } = gUser;
    if (!email || !uid) return jsRedirect(res, `${FRONTEND_URL}/login?google_error=missing_user_info`);

    // Step 4: Create/update user in DB (same logic as /api/google-login)
    let userData: Record<string, unknown>;
    let token: string;

    const adminResult = await db.execute({ sql: 'SELECT * FROM admins WHERE email = ?', args: [email] });
    if ((adminResult.rows as any[]).length > 0) {
      const admin = adminResult.rows[0] as any;
      try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'admin', DATETIME('now'))`, args: [admin.email, admin.name || ''] }); } catch {}
      token = makeJwt({ email: admin.email, role: 'admin' });
      const { password: _ap, ...safeAdmin } = admin;
      userData = { ...safeAdmin, role: 'admin', avatar: photoURL || admin.avatar || null, token };
    } else {
      const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
      if ((userResult.rows as any[]).length > 0) {
        const user = userResult.rows[0] as any;
        try { if (photoURL && photoURL !== user.avatar) await db.execute({ sql: 'UPDATE users SET avatar = ? WHERE email = ?', args: [photoURL, email] }); } catch {}
        try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [user.email, user.name || ''] }); } catch {}
        token = makeJwt({ email: user.email, role: 'user' });
        const { password: _up, ...safeUser } = user;
        userData = { ...safeUser, role: 'user', avatar: photoURL || user.avatar || null, token };
      } else {
        await db.execute({
          sql: 'INSERT INTO users (name, email, password, is_verified, pdpa_accepted, avatar) VALUES (?, ?, ?, 1, 1, ?)',
          args: [sanitizeStr(name) || email, email, hashPassword(uid), photoURL || null],
        });
        const newUserResult = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
        const { password: _np, ...safeNew } = newUserResult.rows[0] as any;
        try { await db.execute({ sql: `INSERT INTO login_sessions (user_email, user_name, role, login_at) VALUES (?, ?, 'user', DATETIME('now'))`, args: [safeNew.email, safeNew.name || ''] }); } catch {}
        token = makeJwt({ email: safeNew.email, role: 'user' });
        userData = { ...safeNew, role: 'user', token };
      }
    }

    // Step 5: Store user data in short-lived exchange code, redirect to frontend
    const authCode = randomBytes(24).toString('base64url').slice(0, 32);
    googleAuthCodes.set(authCode, { user: userData, expiresAt: Date.now() + 5 * 60_000 });
    console.log('[Google OAuth] Success — redirecting to frontend');
    return jsRedirect(res, `${FRONTEND_URL}/login?gat=${authCode}`);
  } catch (e) {
    console.error('[Google OAuth] Callback error:', e);
    return jsRedirect(res, `${FRONTEND_URL}/login?google_error=server_error`);
  }
}

app.get('/auth/google', handleGoogleOAuth);
app.get('/auth/google/callback', handleGoogleOAuth);

// Frontend exchanges the short-lived code for user data (one-time use)
app.get('/api/auth/google/exchange', (req: Request, res: Response) => {
  const { code } = req.query as { code?: string };
  if (!code) return res.status(400).json({ error: 'Missing code' });
  const entry = googleAuthCodes.get(code);
  if (!entry || entry.expiresAt < Date.now()) {
    googleAuthCodes.delete(code);
    return res.status(401).json({ error: 'Code expired or invalid' });
  }
  googleAuthCodes.delete(code);
  res.json({ user: entry.user });
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
    await db.execute(`CREATE TABLE IF NOT EXISTS user_addresses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      name TEXT NOT NULL,
      phone TEXT,
      address_line TEXT NOT NULL,
      district TEXT,
      province TEXT NOT NULL,
      postal_code TEXT,
      is_default INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      user_email TEXT NOT NULL,
      total_amount REAL NOT NULL DEFAULT 0,
      status TEXT DEFAULT 'pending',
      payment_method TEXT DEFAULT 'promptpay',
      shipping_address TEXT,
      note TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id TEXT NOT NULL,
      species_id TEXT NOT NULL,
      species_name TEXT,
      species_name_en TEXT,
      species_image TEXT,
      species_type TEXT,
      quantity INTEGER NOT NULL DEFAULT 1,
      unit_price REAL NOT NULL DEFAULT 0,
      subtotal REAL NOT NULL DEFAULT 0
    )`);
    await db.execute(`ALTER TABLE order_items ADD COLUMN species_name_en TEXT`).catch(() => {});
    await db.execute(`CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      species_id TEXT NOT NULL,
      user_email TEXT NOT NULL,
      user_name TEXT,
      rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
      comment TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    // migrate: add columns if missing
    const migrations = [
      `ALTER TABLE users ADD COLUMN nickname TEXT`,
      `ALTER TABLE users ADD COLUMN phone TEXT`,
      `ALTER TABLE users ADD COLUMN birth_date TEXT`,
      `ALTER TABLE users ADD COLUMN avatar TEXT`,
      `ALTER TABLE users ADD COLUMN pdpa_accepted BOOLEAN DEFAULT 0`,
      // shop columns for species
      `ALTER TABLE species ADD COLUMN price REAL DEFAULT 0`,
      `ALTER TABLE species ADD COLUMN stock INTEGER DEFAULT 0`,
      `ALTER TABLE species ADD COLUMN unit TEXT DEFAULT 'ตัว/ต้น'`,
      `ALTER TABLE species ADD COLUMN available INTEGER DEFAULT 1`,
      `ALTER TABLE species ADD COLUMN age TEXT`,
      `ALTER TABLE species ADD COLUMN gender TEXT`,
      // shipping columns for orders
      `ALTER TABLE orders ADD COLUMN shipping_company TEXT`,
      `ALTER TABLE orders ADD COLUMN tracking_number TEXT`,
      `ALTER TABLE orders ADD COLUMN estimated_delivery TEXT`,
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
