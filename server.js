import fs from 'fs/promises';
import fssync from 'fs';
import path from 'path';
import crypto from 'crypto';
import express from 'express';
import session from 'express-session';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { nanoid } from 'nanoid';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const PORT = Number(process.env.PORT || 5173);
const HOST = process.env.HOST || '0.0.0.0';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_me';

const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

const USER_STORE_PATH = path.join(__dirname, 'data', 'users.json');
const VALID_ROLES = ['superadmin', 'user'];

const TAILADMIN_BUILD_DIR = path.join(
  __dirname,
  'tailadmin-template',
  'tailadmin-free-tailwind-dashboard-template-main',
  'build'
);

const TMP_DIR = path.join(__dirname, 'tmp');

await fs.mkdir(TMP_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, TMP_DIR),
    filename: (_req, file, cb) => cb(null, `${Date.now()}-${nanoid(12)}-${file.originalname}`)
  })
});

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false
    }
  })
);

function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

function requireStreamCreds(req, res, next) {
  if (!req.session?.user?.libraryId || !req.session?.user?.apiKey) {
    return res.status(400).json({ error: 'Stream credentials missing' });
  }
  return next();
}

async function ensureUserStore() {
  await fs.mkdir(path.dirname(USER_STORE_PATH), { recursive: true });

  // If file exists and has users, keep it.
  try {
    const raw = await fs.readFile(USER_STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed?.users) && parsed.users.length > 0) return;
  } catch {
    // ignore
  }

  // Seed from env if provided
  const seedUser = process.env.ADMIN_USERNAME || 'admin';
  const envHash = process.env.ADMIN_PASSWORD_HASH;
  const envPassword = process.env.ADMIN_PASSWORD;
  const seedEmail = process.env.ADMIN_2FA_EMAIL || '';

  // If no password provided, start with empty store; first registration can bootstrap superadmin.
  if (!envHash && !envPassword) {
    await fs.writeFile(USER_STORE_PATH, JSON.stringify({ users: [] }, null, 2), 'utf8');
    return;
  }

  const passwordHash = envHash ? String(envHash) : await bcrypt.hash(String(envPassword), 12);
  const users = [
    {
      username: String(seedUser),
      passwordHash,
      email: String(seedEmail),
      role: 'superadmin',
      libraryId: process.env.SEED_LIBRARY_ID || null,
      apiKey: process.env.SEED_API_KEY || null
    }
  ];
  await fs.writeFile(USER_STORE_PATH, JSON.stringify({ users }, null, 2), 'utf8');
}

async function readUserStore() {
  const raw = await fs.readFile(USER_STORE_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  const users = Array.isArray(parsed?.users) ? parsed.users : [];
  // Ensure default roles on legacy records
  return users.map((u) => ({
    ...u,
    role: VALID_ROLES.includes(u.role) ? u.role : 'user'
  }));
}

async function writeUserStore(users) {
  await fs.writeFile(USER_STORE_PATH, JSON.stringify({ users }, null, 2), 'utf8');
}

async function upsertUser(user) {
  const users = await readUserStore();
  const idx = users.findIndex((u) => String(u.username).toLowerCase() === String(user.username).toLowerCase());
  if (idx >= 0) {
    users[idx] = user;
  } else {
    users.push(user);
  }
  await writeUserStore(users);
}

function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  return {
    ...rest,
    hasPassword: Boolean(passwordHash),
    hasStreamCredentials: Boolean(user.libraryId && user.apiKey)
  };
}

function findUser(users, username) {
  return users.find((u) => String(u.username).toLowerCase() === String(username).toLowerCase());
}

function requireSuperAdmin(req, res, next) {
  if (req.session?.user?.role === 'superadmin') return next();
  return res.status(403).json({ error: 'Forbidden' });
}

async function ensureSuperAdminExistsAfterChange(users) {
  const superAdmins = users.filter((u) => u.role === 'superadmin');
  if (superAdmins.length === 0) {
    throw new Error('At least one superadmin is required');
  }
}

function createMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE || 'false') === 'true';
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass }
  });
}

const mailer = createMailer();
const SMTP_FROM = process.env.SMTP_FROM || 'no-reply@example.com';

const resetTokens = new Map(); // token -> { username, expiresAt }

function randomOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

async function sendEmail(to, subject, text) {
  const activeMailer = mailer || createMailer();
  if (!activeMailer) {
    throw new Error('Email is not configured. Set SMTP_* env vars.');
  }

  await activeMailer.sendMail({
    from: SMTP_FROM,
    to,
    subject,
    text
  });
}

app.get('/health', (req, res) => res.json({ ok: true }));

// TailAdmin compiled assets (CSS/JS/images). Block template HTML pages.
app.use(
  '/tailadmin',
  (req, res, next) => {
    if (String(req.path || '').toLowerCase().endsWith('.html')) {
      return res.status(404).end();
    }
    return next();
  },
  express.static(TAILADMIN_BUILD_DIR)
);

app.get('/', async (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve only the frontend file(s). Avoid exposing server-side data.
app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/README.md', (req, res) => {
  res.status(404).end();
});

app.get('/api/auth/me', (req, res) => {
  res.json({
    authenticated: Boolean(req.session?.authenticated),
    needsOtp: Boolean(req.session?.otp?.pending),
    streamConfigured: Boolean(req.session?.user?.libraryId),
    user: req.session?.user ? sanitizeUser(req.session.user) : null
  });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

    const users = await readUserStore();
    const user = users.find((u) => String(u.username).toLowerCase() === String(username).toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(String(password), String(user.passwordHash));
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    if (!user.email) return res.status(500).json({ error: 'User email not configured for 2FA' });

    const otp = randomOtp();
    req.session.otp = {
      pending: true,
      code: otp,
      expiresAt: Date.now() + 10 * 60 * 1000,
      attempts: 0,
      username: user.username,
      email: user.email,
      role: user.role || 'user',
      libraryId: user.libraryId || null,
      apiKey: user.apiKey || null
    };
    req.session.authenticated = false;

    await sendEmail(
      user.email,
      'Your login verification code',
      `Your verification code is: ${otp}\n\nIt expires in 10 minutes.`
    );

    res.json({ needsOtp: true });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err?.message || 'Login failed' });
  }
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { otp } = req.body || {};
  if (!otp) return res.status(400).json({ error: 'Missing otp' });

  const record = req.session?.otp;
  if (!record?.pending) return res.status(400).json({ error: 'No OTP pending' });
  if (Date.now() > record.expiresAt) return res.status(400).json({ error: 'OTP expired' });

  record.attempts = (record.attempts || 0) + 1;
  if (record.attempts > 8) return res.status(429).json({ error: 'Too many attempts' });

  if (String(otp) !== String(record.code)) return res.status(401).json({ error: 'Invalid OTP' });

  req.session.authenticated = true;
  req.session.user = {
    username: record.username,
    email: record.email,
    role: record.role || 'user',
    libraryId: record.libraryId || null,
    apiKey: record.apiKey || null
  };
  req.session.otp = { pending: false };
  res.json({ authenticated: true });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing currentPassword or newPassword' });

    const users = await readUserStore();
    const currentUser = users.find(
      (u) => String(u.username).toLowerCase() === String(req.session?.user?.username || '').toLowerCase()
    );
    if (!currentUser) return res.status(401).json({ error: 'User not found' });

    const ok = await bcrypt.compare(String(currentPassword), String(currentUser.passwordHash));
    if (!ok) return res.status(401).json({ error: 'Invalid current password' });

    const passwordHash = await bcrypt.hash(String(newPassword), 12);
    currentUser.passwordHash = passwordHash;
    await upsertUser(currentUser);

    res.json({ ok: true });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: err?.message || 'Change password failed' });
  }
});

app.post('/api/auth/request-reset', async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Missing username' });

  // Always return ok to avoid account enumeration.
  const users = await readUserStore();
  const user = users.find((u) => String(u.username).toLowerCase() === String(username).toLowerCase());
  if (!user || !user.email) {
    return res.json({ ok: true });
  }

  const token = nanoid(48);
  resetTokens.set(token, { expiresAt: Date.now() + 30 * 60 * 1000, username: user.username });

  const link = `${APP_BASE_URL}/?resetToken=${encodeURIComponent(token)}`;
  try {
    await sendEmail(
      user.email,
      'Password reset',
      `A password reset was requested for your account.\n\nOpen this link to reset your password (expires in 30 minutes):\n${link}`
    );
  } catch (err) {
    console.error('Reset email error:', err);
    // Return ok to avoid enumeration; email failures are logged.
  }

  res.json({ ok: true });
});

app.get('/api/session/stream-info', requireAuth, requireStreamCreds, (req, res) => {
  res.json({
    libraryId: req.session.user.libraryId
  });
});

app.post('/api/uploads/presign', requireAuth, requireStreamCreds, async (req, res) => {
  try {
    const { title, filetype, collectionId } = req.body || {};

    const safeTitle = title ? String(title) : 'Untitled';
    const safeFiletype = filetype ? String(filetype) : 'application/octet-stream';
    const safeCollectionId = collectionId ? String(collectionId) : null;

    // Step 1: create video object
    const create = await streamFetch(req, '/videos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: safeTitle,
        ...(safeCollectionId ? { collectionId: safeCollectionId } : {})
      })
    });

    if (!create.ok) {
      const text = await create.text();
      return res.status(create.status).type(create.headers.get('content-type') || 'application/json').send(text);
    }

    const created = await create.json();
    const videoGuid = created.guid;

    // Step 2: generate presigned signature
    const { libraryId, apiKey } = req.session.user || {};
    const expire = Math.floor(Date.now() / 1000) + 15 * 60;
    const signature = sha256Hex(`${libraryId}${apiKey}${expire}${videoGuid}`);

    res.json({
      endpoint: 'https://video.bunnycdn.com/tusupload',
      headers: {
        AuthorizationSignature: signature,
        AuthorizationExpire: expire,
        VideoId: videoGuid,
        LibraryId: libraryId
      },
      metadata: {
        filetype: safeFiletype,
        title: safeTitle,
        ...(safeCollectionId ? { collection: safeCollectionId } : {})
      },
      videoGuid
    });
  } catch (err) {
    console.error('Presign error:', err);
    res.status(500).json({ error: err?.message || 'Presign failed' });
  }
});

app.post('/api/auth/reset', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: 'Missing token or newPassword' });

  const rec = resetTokens.get(String(token));
  if (!rec) return res.status(400).json({ error: 'Invalid token' });
  if (Date.now() > rec.expiresAt) {
    resetTokens.delete(String(token));
    return res.status(400).json({ error: 'Token expired' });
  }

  const users = await readUserStore();
  const user = users.find((u) => String(u.username).toLowerCase() === String(rec.username).toLowerCase());
  if (!user) return res.status(400).json({ error: 'Invalid token' });

  const passwordHash = await bcrypt.hash(String(newPassword), 12);
  user.passwordHash = passwordHash;
  await upsertUser(user);
  resetTokens.delete(String(token));

  // Force re-login
  req.session.authenticated = false;
  req.session.otp = { pending: false };
  req.session.user = null;

  res.json({ ok: true });
});

app.post('/api/session/stream-credentials', requireAuth, (req, res) => {
  // Deprecated: keep for backward compatibility, restrict to superadmin and target user via username
  res.status(410).json({ error: 'Endpoint deprecated. Stream credentials are managed by superadmin per user.' });
});

async function streamFetch(req, pathPart, init = {}) {
  const { libraryId, apiKey } = req.session.user || {};
  const url = `https://video.bunnycdn.com/library/${encodeURIComponent(libraryId)}${pathPart}`;

  const headers = {
    ...(init.headers || {}),
    AccessKey: apiKey,
    Accept: 'application/json'
  };

  return fetch(url, { ...init, headers });
}

app.get('/api/collections', requireAuth, requireStreamCreds, async (req, res) => {
  const r = await streamFetch(req, '/collections', { method: 'GET' });
  const text = await r.text();
  res.status(r.status).type(r.headers.get('content-type') || 'application/json').send(text);
});

app.get('/api/videos', requireAuth, requireStreamCreds, async (req, res) => {
  const r = await streamFetch(req, '/videos', { method: 'GET' });
  const text = await r.text();
  res.status(r.status).type(r.headers.get('content-type') || 'application/json').send(text);
});

app.post('/api/videos/:videoGuid', requireAuth, requireStreamCreds, async (req, res) => {
  const { videoGuid } = req.params;
  const r = await streamFetch(req, `/videos/${encodeURIComponent(videoGuid)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req.body || {})
  });

  const text = await r.text();
  res.status(r.status).type(r.headers.get('content-type') || 'application/json').send(text);
});

app.delete('/api/videos/:videoGuid', requireAuth, requireStreamCreds, async (req, res) => {
  const { videoGuid } = req.params;
  const r = await streamFetch(req, `/videos/${encodeURIComponent(videoGuid)}`, { method: 'DELETE' });
  const text = await r.text();
  res.status(r.status).type(r.headers.get('content-type') || 'application/json').send(text);
});

app.post('/api/videos/upload', requireAuth, requireStreamCreds, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Missing file' });

  const tempPath = file.path;

  try {
    const title = req.body?.title ? String(req.body.title) : file.originalname;
    const collectionId = req.body?.collectionId ? String(req.body.collectionId) : null;

    // Step 1: create video
    const create = await streamFetch(req, '/videos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        ...(collectionId ? { collectionId } : {})
      })
    });

    if (!create.ok) {
      const text = await create.text();
      return res.status(create.status).type(create.headers.get('content-type') || 'application/json').send(text);
    }

    const created = await create.json();
    const guid = created.guid;

    // Step 2: stream file to upstream
    const { libraryId, apiKey } = req.session.user || {};
    const putUrl = `https://video.bunnycdn.com/library/${encodeURIComponent(libraryId)}/videos/${encodeURIComponent(guid)}`;

    const readStream = fssync.createReadStream(tempPath);
    const put = await fetch(putUrl, {
      method: 'PUT',
      headers: { AccessKey: apiKey },
      // Required by Node fetch when streaming request bodies
      duplex: 'half',
      body: readStream
    });

    if (!put.ok) {
      const text = await put.text();
      return res.status(put.status).type(put.headers.get('content-type') || 'text/plain').send(text);
    }

    res.json({ ok: true, guid });
  } catch (err) {
    console.error('Upload endpoint error:', err);
    res.status(500).json({ error: err?.message || 'Upload failed' });
  } finally {
    if (tempPath) {
      fs.unlink(tempPath).catch(() => {});
    }
  }
});

app.get('/api/thumb/:videoGuid/:fileName', requireAuth, requireStreamCreds, async (req, res) => {
  const { videoGuid, fileName } = req.params;
  const { libraryId } = req.session.user || {};

  const upstream = `https://${encodeURIComponent(libraryId)}.b-cdn.net/${encodeURIComponent(videoGuid)}/${encodeURIComponent(fileName)}`;
  const r = await fetch(upstream, { method: 'GET' });

  if (!r.ok) {
    return res.status(r.status).send('');
  }

  res.status(200);
  const ct = r.headers.get('content-type');
  if (ct) res.setHeader('Content-Type', ct);

  const buf = Buffer.from(await r.arrayBuffer());
  res.send(buf);
});

// --- Superadmin user management ---
app.get('/api/admin/users', requireAuth, requireSuperAdmin, async (_req, res) => {
  const users = await readUserStore();
  res.json({ users: users.map(sanitizeUser) });
});

app.post('/api/admin/users', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { username, password, email, role = 'user', libraryId = null, apiKey = null } = req.body || {};
    if (!username || !password || !email) return res.status(400).json({ error: 'Missing username, password, or email' });
    if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const users = await readUserStore();
    if (findUser(users, username)) return res.status(409).json({ error: 'Username already exists' });

    const passwordHash = await bcrypt.hash(String(password), 12);
    await upsertUser({
      username: String(username),
      passwordHash,
      email: String(email),
      role,
      libraryId: libraryId ? String(libraryId).trim() : null,
      apiKey: apiKey ? String(apiKey).trim() : null
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('Create user error:', err);
    res.status(500).json({ error: err?.message || 'Create user failed' });
  }
});

app.patch('/api/admin/users/:username', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const targetUsername = req.params.username;
    const { email, password, role, libraryId, apiKey } = req.body || {};

    const users = await readUserStore();
    const user = findUser(users, targetUsername);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (role && !VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });

    if (email !== undefined) user.email = String(email);
    if (libraryId !== undefined) user.libraryId = libraryId ? String(libraryId).trim() : null;
    if (apiKey !== undefined) user.apiKey = apiKey ? String(apiKey).trim() : null;
    if (role !== undefined) user.role = role;
    if (password) {
      user.passwordHash = await bcrypt.hash(String(password), 12);
    }

    await upsertUser(user);
    const all = await readUserStore();
    await ensureSuperAdminExistsAfterChange(all);

    // If updated user matches current session, refresh session data
    if (req.session?.user && String(req.session.user.username).toLowerCase() === String(user.username).toLowerCase()) {
      req.session.user = {
        username: user.username,
        email: user.email,
        role: user.role,
        libraryId: user.libraryId || null,
        apiKey: user.apiKey || null
      };
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: err?.message || 'Update user failed' });
  }
});

app.delete('/api/admin/users/:username', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const targetUsername = req.params.username;
    const users = await readUserStore();
    const idx = users.findIndex((u) => String(u.username).toLowerCase() === String(targetUsername).toLowerCase());
    if (idx === -1) return res.status(404).json({ error: 'User not found' });

    const removing = users[idx];
    const next = [...users];
    next.splice(idx, 1);
    await ensureSuperAdminExistsAfterChange(next);
    await writeUserStore(next);

    res.json({ ok: true });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: err?.message || 'Delete user failed' });
  }
});

// Registration endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, email } = req.body || {};
    if (!username || !password || !email) return res.status(400).json({ error: 'Missing username, password, or email' });

    const users = await readUserStore();
    const exists = findUser(users, username);
    if (exists) return res.status(409).json({ error: 'Username already exists' });

    const passwordHash = await bcrypt.hash(String(password), 12);
    await upsertUser({
      username: String(username),
      passwordHash,
      email: String(email),
      role: users.length === 0 ? 'superadmin' : 'user',
      libraryId: null,
      apiKey: null
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: err?.message || 'Registration failed' });
  }
});

await ensureUserStore();

app.listen(PORT, HOST, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
