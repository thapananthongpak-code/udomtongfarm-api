import express from 'express';
import cors from 'cors';
import { createClient } from '@libsql/client';
import nodemailer from 'nodemailer'; // 🟢 เปลี่ยนมาใช้ nodemailer

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const db = createClient({
  url: "libsql://udomthongfarm-db-thapananthongpak.aws-ap-northeast-1.turso.io",
  authToken: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NzI2MjcxMTcsImlkIjoiMDE5Y2I3ZWUtZDkwMS03NWRiLWI4MTMtNDQ0Yjk0NzJmMDc4IiwicmlkIjoiMDk4YTc0NjUtNDk4OC00OWNlLWFmOTctMmI2YjQwNzgwMzE1In0.R092Y3mlJL5Khd2dqojr8uf6jURd_lwvBekrKzbIPuJNWgkuf259sOm3A27QeVOf0tgZJ2-ekoAzBaXaUsS9BA",
});

// 🟢 ตั้งค่าระบบส่งอีเมลผ่าน Gmail ด้วยรหัสผ่านแอปที่คุณให้มา
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'thapananthongpak@gmail.com', // อีเมลแอดมิน
    pass: 'tmlczptnqdphwjhq'            // รหัสผ่านแอป 16 หลัก
  }
});

// 🟢 0. ตัวช่วยพิเศษ: ล้างบัญชีที่ "ติดแหงก" (ยังไม่ยืนยัน OTP) ทิ้งไป เพื่อให้สมัครใหม่ได้
app.get('/cleanup-users', async (req, res) => {
  try {
    await db.execute(`DELETE FROM users WHERE is_verified = 0`);
    res.json({ message: "ล้างบัญชีที่ค้าง (ยังไม่ยืนยัน OTP) ออกหมดแล้ว! คุณสามารถใช้อีเมลเดิมสมัครใหม่ได้เลย ✅" });
  } catch (error) {
    res.status(500).json({ error: "ลบข้อมูลไม่สำเร็จ" });
  }
});

app.get('/upgrade-db', async (req, res) => {
  try {
    await db.execute(`ALTER TABLE users ADD COLUMN nickname TEXT;`);
    await db.execute(`ALTER TABLE users ADD COLUMN phone TEXT;`);
    await db.execute(`ALTER TABLE users ADD COLUMN birth_date TEXT;`);
    await db.execute(`ALTER TABLE users ADD COLUMN pdpa_accepted BOOLEAN DEFAULT 0;`);
    res.json({ message: "อัปเกรดตาราง Users สำเร็จ! ✅" });
  } catch (error) { res.json({ message: "ตารางมีคอลัมน์เหล่านี้อยู่แล้ว 👍" }); }
});

app.get('/setup-db', async (req, res) => {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, nickname TEXT, phone TEXT, birth_date TEXT, email TEXT UNIQUE, password TEXT, pdpa_accepted BOOLEAN DEFAULT 0, is_verified BOOLEAN DEFAULT 0);`);
    await db.execute(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT);`);
    await db.execute(`CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, otp_code TEXT, expires_at DATETIME);`);
    res.json({ message: "สร้างตารางพื้นฐานสำเร็จแล้ว! ✅" });
  } catch (error) { res.status(500).json({ error: "Setup Failed" }); }
});

app.get('/setup-species', async (req, res) => {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS species (id TEXT PRIMARY KEY, type TEXT NOT NULL, name_th TEXT NOT NULL, name_en TEXT NOT NULL, scientific_name TEXT, short_description TEXT, description TEXT, image TEXT, tags TEXT, references_data TEXT);`);
    res.json({ message: "สร้างตาราง species สำหรับเก็บข้อมูลฟาร์มสำเร็จแล้ว! 🐾" });
  } catch (error) { res.status(500).json({ error: "Setup species failed" }); }
});

app.get('/setup-admin', async (req, res) => {
  try {
    const checkAdmin = await db.execute(`SELECT * FROM admins WHERE email = 'thapananthongpak@gmail.com'`);
    if (checkAdmin.rows.length === 0) {
      await db.execute({ sql: `INSERT INTO admins (name, email, password) VALUES (?, ?, ?)`, args: ["Owner", "thapananthongpak@gmail.com", "admin1234"] });
      return res.json({ message: "สร้างบัญชี Admin ของคุณสำเร็จ! ✅" });
    }
    res.json({ message: "ระบบมีบัญชี Admin อยู่แล้ว 👍" });
  } catch (error) { res.status(500).json({ error: "Admin Setup Failed" }); }
});

app.get('/api/admins', async (req, res) => {
  try { const result = await db.execute("SELECT email, name FROM admins"); res.json(result.rows); } catch (e) { res.status(500).json({ error: "Fetch failed" }); }
});

app.post('/api/admins', async (req, res) => {
  const { email } = req.body;
  try { await db.execute({ sql: "INSERT INTO admins (name, email, password) VALUES (?, ?, ?)", args: ["Extra Admin", email, "admin1234"] }); res.json({ message: "เพิ่ม Admin สำเร็จ!" }); } catch (e) { res.status(400).json({ error: "อีเมลนี้เป็นแอดมินอยู่แล้ว" }); }
});

app.delete('/api/admins/:email', async (req, res) => {
  try { if (req.params.email === 'thapananthongpak@gmail.com') return res.status(403).json({ error: "ลบ Owner ไม่ได้" }); await db.execute({ sql: "DELETE FROM admins WHERE email = ?", args: [req.params.email] }); res.json({ message: "ลบ Admin สำเร็จ" }); } catch (e) { res.status(500).json({ error: "Delete failed" }); }
});

app.get('/api/species', async (req, res) => {
  try { const result = await db.execute("SELECT * FROM species"); res.json(result.rows.map((row: any) => ({ ...row, tags: JSON.parse(row.tags || "[]"), references: JSON.parse(row.references_data || "[]") }))); } catch (error) { res.status(500).json({ error: "Failed to fetch species" }); }
});

app.post('/api/species', async (req, res) => {
  const { id, type, name_th, name_en, scientific_name, short_description, description, image, tags, references } = req.body;
  try { await db.execute({ sql: `INSERT OR REPLACE INTO species (id, type, name_th, name_en, scientific_name, short_description, description, image, tags, references_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args: [id, type, name_th, name_en, scientific_name, short_description, description, image, JSON.stringify(tags || []), JSON.stringify(references || [])] }); res.json({ message: "บันทึกข้อมูลสำเร็จ!" }); } catch (error) { res.status(500).json({ error: "Failed to save species" }); }
});

app.delete('/api/species/:id', async (req, res) => {
  try { await db.execute({ sql: "DELETE FROM species WHERE id = ?", args: [req.params.id] }); res.json({ message: "ลบข้อมูลสำเร็จ!" }); } catch (error) { res.status(500).json({ error: "Failed to delete" }); }
});

app.post('/api/register', async (req, res) => {
  const { email, password, name, nickname, phone, birthDate, pdpa } = req.body;
  try {
    const userCheck = await db.execute({ sql: "SELECT id, is_verified FROM users WHERE email = ?", args: [email] });
    const adminCheck = await db.execute({ sql: "SELECT id FROM admins WHERE email = ?", args: [email] });
    if (adminCheck.rows.length > 0) return res.status(400).json({ error: "อีเมลนี้มีในระบบแล้ว" });
    if (userCheck.rows.length > 0) {
      const existingUser = userCheck.rows[0] as any;
      if (existingUser.is_verified === 1) return res.status(400).json({ error: "อีเมลนี้มีในระบบแล้ว" });
      // ลบบัญชีเก่าที่ยังไม่ verified เพื่อให้สมัครใหม่ได้
      await db.execute({ sql: "DELETE FROM users WHERE email = ?", args: [email] });
      await db.execute({ sql: "DELETE FROM otps WHERE email = ?", args: [email] });
    }

    await db.execute({ 
      sql: "INSERT INTO users (name, nickname, phone, birth_date, email, password, pdpa_accepted, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, 0)", 
      args: [name || "", nickname || "", phone || "", birthDate || "", email, password, pdpa ? 1 : 0] 
    });

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60000).toISOString();
    await db.execute({ sql: "INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)", args: [email, otpCode, expiresAt] });

    // 🟢 โชว์รหัส OTP บนหน้าจอ Terminal ให้เห็นชัดๆ
    console.log("\n=========================================");
    console.log(`🔐 รหัส OTP ของ ${email} คือ: >>> ${otpCode} <<<`);
    console.log("=========================================\n");

    // 🟢 ใช้ Nodemailer ส่งอีเมล
    await transporter.sendMail({
      from: '"Udomthongfarm" <thapananthongpak@gmail.com>', 
      to: email, 
      subject: 'รหัส OTP สมัครสมาชิก Udomthongfarm', 
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2 style="color: #0f172a;">ยินดีต้อนรับสู่ Udomthong Farm</h2>
          <p>รหัส OTP สำหรับยืนยันอีเมลของคุณคือ:</p>
          <h1 style="color: #2563eb; letter-spacing: 5px;">${otpCode}</h1>
        </div>
      ` 
    });
    
    res.json({ message: "สมัครสมาชิกสำเร็จ!" });
  } catch (error) { 
    console.error("❌ Email Error:", error);
    res.status(500).json({ error: "Register Failed" }); 
  }
});

app.post('/api/verify-otp', async (req, res) => {
  const { email, otpCode } = req.body;
  try {
    const result = await db.execute({ sql: "SELECT * FROM otps WHERE email = ? AND otp_code = ? AND expires_at > DATETIME('now') ORDER BY id DESC LIMIT 1", args: [email, otpCode] });
    if (result.rows.length === 0) return res.status(400).json({ error: "OTP ไม่ถูกต้องหรือหมดอายุ" });
    await db.execute({ sql: "UPDATE users SET is_verified = 1 WHERE email = ?", args: [email] });
    await db.execute({ sql: "DELETE FROM otps WHERE email = ?", args: [email] });
    res.json({ message: "ยืนยันอีเมลสำเร็จ!" });
  } catch (error) { res.status(500).json({ error: "Verify Failed" }); }
});

app.post('/api/google-login', async (req, res) => {
  const { email, name, uid } = req.body;
  try {
    // ตรวจว่าเป็น admin ไหม
    const adminResult = await db.execute({ sql: "SELECT * FROM admins WHERE email = ?", args: [email] });
    if (adminResult.rows.length > 0) {
      return res.json({ message: "แอดมินเข้าสู่ระบบสำเร็จ", user: { ...(adminResult.rows[0] as any), role: 'admin' } });
    }

    // ตรวจว่ามี user อยู่แล้วไหม
    const userResult = await db.execute({ sql: "SELECT * FROM users WHERE email = ?", args: [email] });
    if (userResult.rows.length > 0) {
      const user = userResult.rows[0] as any;
      return res.json({ message: "เข้าสู่ระบบสำเร็จ", user: { ...user, role: 'user' } });
    }

    // สร้าง user ใหม่อัตโนมัติ (Google verified แล้ว ไม่ต้อง OTP)
    await db.execute({
      sql: "INSERT INTO users (name, email, password, is_verified, pdpa_accepted) VALUES (?, ?, ?, 1, 1)",
      args: [name || email, email, uid]
    });
    const newUser = await db.execute({ sql: "SELECT * FROM users WHERE email = ?", args: [email] });
    return res.json({ message: "สร้างบัญชีและเข้าสู่ระบบสำเร็จ", user: { ...(newUser.rows[0] as any), role: 'user' } });
  } catch (error) {
    res.status(500).json({ error: "Google Login Failed" });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const adminResult = await db.execute({ sql: "SELECT * FROM admins WHERE email = ? AND password = ?", args: [email, password] });
    if (adminResult.rows.length > 0) return res.json({ message: "แอดมินเข้าสู่ระบบสำเร็จ", user: { ...(adminResult.rows[0] as any), role: 'admin' } });
    
    const userResult = await db.execute({ sql: "SELECT * FROM users WHERE email = ? AND password = ?", args: [email, password] });
    if (userResult.rows.length > 0) {
      const user = userResult.rows[0] as any;
      if (user.is_verified === 0) return res.status(403).json({ error: "กรุณายืนยันอีเมลก่อน" });
      return res.json({ message: "เข้าสู่ระบบสำเร็จ", user: { ...user, role: 'user' } });
    }
    res.status(401).json({ error: "ข้อมูลไม่ถูกต้อง" });
  } catch (error) { res.status(500).json({ error: "Login Failed" }); }
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const userCheck = await db.execute({ sql: "SELECT email FROM users WHERE email = ?", args: [email] });
    const adminCheck = await db.execute({ sql: "SELECT email FROM admins WHERE email = ?", args: [email] });
    if (userCheck.rows.length === 0 && adminCheck.rows.length === 0) return res.status(400).json({ error: "ไม่พบอีเมลนี้" });

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60000).toISOString();
    await db.execute({ sql: "INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)", args: [email, otpCode, expiresAt] });

    // 🟢 โชว์รหัส OTP บนหน้าจอ Terminal ให้เห็นชัดๆ
    console.log("\n=========================================");
    console.log(`🔐 รหัส OTP รีเซ็ตรหัสผ่านของ ${email} คือ: >>> ${otpCode} <<<`);
    console.log("=========================================\n");

    // 🟢 ใช้ Nodemailer ส่งอีเมล
    await transporter.sendMail({ 
      from: '"Udomthongfarm" <thapananthongpak@gmail.com>', 
      to: email, 
      subject: 'รหัส OTP รีเซ็ตรหัสผ่าน Udomthongfarm', 
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2 style="color: #0f172a;">คำขอรีเซ็ตรหัสผ่าน</h2>
          <p>รหัส OTP ของคุณคือ:</p>
          <h1 style="color: #22c55e; letter-spacing: 5px;">${otpCode}</h1>
        </div>
      ` 
    });

    res.json({ message: "ส่ง OTP แล้ว" });
  } catch (error) { 
    console.error("❌ Email Error:", error);
    res.status(500).json({ error: "Forgot Password Failed" }); 
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { email, otpCode, newPassword } = req.body;
  try {
    const result = await db.execute({ sql: "SELECT * FROM otps WHERE email = ? AND otp_code = ? AND expires_at > DATETIME('now') ORDER BY id DESC LIMIT 1", args: [email, otpCode] });
    if (result.rows.length === 0) return res.status(400).json({ error: "OTP ไม่ถูกต้อง" });
    const adminCheck = await db.execute({ sql: "SELECT email FROM admins WHERE email = ?", args: [email] });
    const table = adminCheck.rows.length > 0 ? "admins" : "users";
    await db.execute({ sql: `UPDATE ${table} SET password = ? WHERE email = ?`, args: [newPassword, email] });
    await db.execute({ sql: "DELETE FROM otps WHERE email = ?", args: [email] });
    res.json({ message: "เปลี่ยนรหัสผ่านสำเร็จ!" });
  } catch (error) { res.status(500).json({ error: "Reset Failed" }); }
});

app.listen(port, () => { console.log(`🚀 Udomthong API พร้อมทำงานที่: http://localhost:${port}`); });