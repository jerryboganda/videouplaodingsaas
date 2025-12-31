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

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_2FA_EMAIL = process.env.ADMIN_2FA_EMAIL || '';
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

const ADMIN_STORE_PATH = path.join(__dirname, 'data', 'admin.json');

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
  if (!req.session?.stream?.libraryId || !req.session?.stream?.apiKey) {
    return res.status(400).json({ error: 'Stream credentials missing' });
  }
  return next();
}

async function ensureAdminStore() {
  await fs.mkdir(path.dirname(ADMIN_STORE_PATH), { recursive: true });

  const envHash = process.env.ADMIN_PASSWORD_HASH;
  const envPassword = process.env.ADMIN_PASSWORD;

  // Always prefer environment configuration if provided. This ensures changes to
  // ADMIN_PASSWORD take effect even if admin.json already exists.
  if (envHash || envPassword) {
    const passwordHash = envHash ? String(envHash) : await bcrypt.hash(String(envPassword), 12);
    const store = { passwordHash };
    await fs.writeFile(ADMIN_STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
    return;
  }

  // Fall back to existing store if no env credentials are provided.
  try {
    const raw = await fs.readFile(ADMIN_STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed?.passwordHash) return;
  } catch {
    // ignore
  }

  throw new Error('Missing ADMIN_PASSWORD or ADMIN_PASSWORD_HASH in environment');
}

async function readAdminStore() {
  const raw = await fs.readFile(ADMIN_STORE_PATH, 'utf8');
  return JSON.parse(raw);
}

async function writeAdminStore(next) {
  await fs.writeFile(ADMIN_STORE_PATH, JSON.stringify(next, null, 2), 'utf8');
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

const resetTokens = new Map();

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
    streamConfigured: Boolean(req.session?.stream?.libraryId)
  });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
    if (String(username) !== String(ADMIN_USERNAME)) return res.status(401).json({ error: 'Invalid credentials' });

    const store = await readAdminStore();
    const ok = await bcrypt.compare(String(password), String(store.passwordHash));
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    if (!ADMIN_2FA_EMAIL) return res.status(500).json({ error: '2FA email not configured' });

    const otp = randomOtp();
    req.session.otp = {
      pending: true,
      code: otp,
      expiresAt: Date.now() + 10 * 60 * 1000,
      attempts: 0
    };
    req.session.authenticated = false;

    await sendEmail(
      ADMIN_2FA_EMAIL,
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

    const store = await readAdminStore();
    const ok = await bcrypt.compare(String(currentPassword), String(store.passwordHash));
    if (!ok) return res.status(401).json({ error: 'Invalid current password' });

    const passwordHash = await bcrypt.hash(String(newPassword), 12);
    await writeAdminStore({ passwordHash });

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
  if (String(username) !== String(ADMIN_USERNAME) || !ADMIN_2FA_EMAIL) {
    return res.json({ ok: true });
  }

  const token = nanoid(48);
  resetTokens.set(token, { expiresAt: Date.now() + 30 * 60 * 1000 });

  const link = `${APP_BASE_URL}/?resetToken=${encodeURIComponent(token)}`;
  try {
    await sendEmail(
      ADMIN_2FA_EMAIL,
      'Password reset',
      `A password reset was requested.\n\nOpen this link to reset your password (expires in 30 minutes):\n${link}`
    );
  } catch (err) {
    console.error('Reset email error:', err);
    // Return ok to avoid enumeration; email failures are logged.
  }

  res.json({ ok: true });
});

app.get('/api/session/stream-info', requireAuth, requireStreamCreds, (req, res) => {
  res.json({
    libraryId: req.session.stream.libraryId
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
    const { libraryId, apiKey } = req.session.stream;
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

  const passwordHash = await bcrypt.hash(String(newPassword), 12);
  await writeAdminStore({ passwordHash });
  resetTokens.delete(String(token));

  // Force re-login
  req.session.authenticated = false;
  req.session.otp = { pending: false };

  res.json({ ok: true });
});

app.post('/api/session/stream-credentials', requireAuth, (req, res) => {
  const { libraryId, apiKey } = req.body || {};
  if (!libraryId || !apiKey) return res.status(400).json({ error: 'Missing libraryId/apiKey' });

  req.session.stream = {
    libraryId: String(libraryId).trim(),
    apiKey: String(apiKey).trim()
  };

  res.json({ ok: true });
});

async function streamFetch(req, pathPart, init = {}) {
  const { libraryId, apiKey } = req.session.stream;
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
    const { libraryId, apiKey } = req.session.stream;
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
  const { libraryId } = req.session.stream;

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

await ensureAdminStore();

app.listen(PORT, HOST, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
