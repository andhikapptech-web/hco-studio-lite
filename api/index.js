require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const fsSync = require('fs');
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');
const AdmZip = require('adm-zip');
const { createClient } = require('@supabase/supabase-js');

const execFileAsync = promisify(execFile);
const app = express();

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'default_jwt_secret_change_me_immediately_12345';
const ENCRYPTION_SECRET = crypto
  .createHash('sha256')
  .update(process.env.ENCRYPTION_SECRET || 'default_aes_secret_change_me_immediately')
  .digest();

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'ADMINHCO';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Tama010511';

const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

// --- SECURITY HEADERS & MIDDLEWARE ---
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- SIMPLE RATE LIMITER (Anti Brute Force & Spam) ---
const rateMap = new Map();
function rateLimit(maxReqs, windowMs) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const key = `${req.path}:${ip}`;
    const now = Date.now();
    const record = rateMap.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > record.resetAt) {
      record.count = 0;
      record.resetAt = now + windowMs;
    }
    record.count += 1;
    rateMap.set(key, record);
    if (record.count > maxReqs) {
      return res.status(429).json({ error: 'Terlalu banyak permintaan. Silakan tunggu beberapa saat.' });
    }
    next();
  };
}

// --- CRYPTO HELPERS (Password Scrypt, JWT HMAC, AES-256-GCM) ---
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, originalHash] = String(stored).split(':');
  if (!salt || !originalHash) return false;
  const hashBuf = crypto.scryptSync(password, salt, 64);
  const origBuf = Buffer.from(originalHash, 'hex');
  if (hashBuf.length !== origBuf.length) return false;
  return crypto.timingSafeEqual(hashBuf, origBuf);
}

function signToken(payload) {
  const data = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function encryptApiKey(rawKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_SECRET, iv);
  const encrypted = Buffer.concat([cipher.update(rawKey, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptApiKey(stored) {
  if (!stored) return '';
  const [ivHex, tagHex, encHex] = stored.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_SECRET, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]);
  return decrypted.toString('utf8');
}

// --- SEED ADMIN ACCOUNT (ADMINHCO) ---
let adminSeeded = false;
async function ensureAdminExists() {
  if (adminSeeded || !supabase) return;
  try {
    const { data: existing } = await supabase
      .from('users')
      .select('id, role')
      .eq('username', ADMIN_USERNAME)
      .maybeSingle();

    if (!existing) {
      await supabase.from('users').insert({
        username: ADMIN_USERNAME,
        password_hash: hashPassword(ADMIN_PASSWORD),
        role: 'admin',
        credits: 999999,
        free_rbxl_vouchers: 999,
        free_rbxm_vouchers: 999
      });
    } else if (existing.role !== 'admin') {
      await supabase
        .from('users')
        .update({ role: 'admin', password_hash: hashPassword(ADMIN_PASSWORD) })
        .eq('id', existing.id);
    }
    adminSeeded = true;
  } catch (err) {
    console.error('Admin seed warning:', err.message);
  }
}

// --- AUTH MIDDLEWARE ---
async function requireAuth(req, res, next) {
  if (!supabase) {
    return res.status(500).json({ error: 'Database Supabase belum dikonfigurasi di Environment Variables.' });
  }
  await ensureAdminExists();
  const token = req.cookies.auth_token || (req.headers.authorization || '').replace('Bearer ', '');
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Sesi berakhir. Silakan login kembali.' });
  }
  const { data: user } = await supabase
    .from('users')
    .select('id, username, role, credits, free_rbxl_vouchers, free_rbxm_vouchers, roblox_user_id, roblox_universe_id, roblox_place_id, encrypted_api_key, api_key_hint')
    .eq('id', decoded.id)
    .maybeSingle();

  if (!user) {
    return res.status(401).json({ error: 'Akun tidak ditemukan.' });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Akses ditolak. Khusus Admin.' });
  }
  next();
}

// --- CREDIT PRICING CALCULATOR ---
function calculateCreditCost(ext, sizeBytes) {
  const sizeMB = Math.max(1, Math.ceil(sizeBytes / (1024 * 1024)));
  const isPlace = ext === '.rbxl' || ext === '.rbxlx';
  if (isPlace) {
    return 10 + sizeMB * 3; // Base 10 credit + 3 credit/MB untuk .rbxl/.rbxlx
  }
  return 5 + sizeMB * 2; // Base 5 credit + 2 credit/MB untuk .rbxm/.rbxmx
}

// --- AUTO-GET LUNE BINARY (Supports Local Windows & Vercel Linux) ---
async function getLuneBinary() {
  if (process.env.LUNE_PATH && fsSync.existsSync(process.env.LUNE_PATH)) {
    return process.env.LUNE_PATH;
  }
  const localWin = path.join(__dirname, '..', 'lune.exe');
  if (fsSync.existsSync(localWin)) return localWin;

  if (process.platform === 'linux') {
    const tmpLune = '/tmp/lune';
    if (fsSync.existsSync(tmpLune)) return tmpLune;

    const releaseUrl = 'https://github.com/lune-org/lune/releases/download/v0.8.9/lune-0.8.9-linux-x86_64.zip';
    const res = await fetch(releaseUrl);
    if (!res.ok) throw new Error('Gagal mengunduh runtime Lune di Vercel.');
    const zipBuffer = Buffer.from(await res.arrayBuffer());
    const zip = new AdmZip(zipBuffer);
    zip.extractAllTo('/tmp', true);
    await fs.chmod(tmpLune, 0o755);
    return tmpLune;
  }

  return 'lune';
}

// --- AUTH ROUTES ---
app.post('/api/auth/register', rateLimit(10, 60 * 1000), async (req, res) => {
  await ensureAdminExists();
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({ error: 'Username harus 3-24 karakter (huruf, angka, atau underscore).' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password minimal 6 karakter.' });
  }

  const { data: exists } = await supabase.from('users').select('id').ilike('username', username).maybeSingle();
  if (exists) {
    return res.status(400).json({ error: 'Username sudah terdaftar.' });
  }

  const { data: newUser, error } = await supabase
    .from('users')
    .insert({
      username,
      password_hash: hashPassword(password),
      role: 'user',
      credits: 0,
      free_rbxl_vouchers: 0,
      free_rbxm_vouchers: 0
    })
    .select('id, username, role, credits, free_rbxl_vouchers, free_rbxm_vouchers')
    .single();

  if (error) return res.status(500).json({ error: error.message });

  const token = signToken({ id: newUser.id, username: newUser.username, role: newUser.role });
  res.cookie('auth_token', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 3600 * 1000 });
  res.json({ user: newUser });
});

app.post('/api/auth/login', rateLimit(15, 60 * 1000), async (req, res) => {
  await ensureAdminExists();
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  const { data: user } = await supabase
    .from('users')
    .select('*')
    .ilike('username', username)
    .maybeSingle();

  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'Username atau password salah.' });
  }

  const token = signToken({ id: user.id, username: user.username, role: user.role });
  res.cookie('auth_token', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 3600 * 1000 });
  res.json({
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      credits: user.credits,
      free_rbxl_vouchers: user.free_rbxl_vouchers,
      free_rbxm_vouchers: user.free_rbxm_vouchers,
      roblox_user_id: user.roblox_user_id,
      roblox_universe_id: user.roblox_universe_id,
      roblox_place_id: user.roblox_place_id,
      api_key_hint: user.api_key_hint
    }
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const u = req.user;
  const { data: logs } = await supabase
    .from('upload_logs')
    .select('*')
    .eq('user_id', u.id)
    .order('created_at', { ascending: false })
    .limit(20);

  res.json({
    user: {
      id: u.id,
      username: u.username,
      role: u.role,
      credits: u.credits,
      free_rbxl_vouchers: u.free_rbxl_vouchers,
      free_rbxm_vouchers: u.free_rbxm_vouchers,
      roblox_user_id: u.roblox_user_id,
      roblox_universe_id: u.roblox_universe_id,
      roblox_place_id: u.roblox_place_id,
      api_key_hint: u.api_key_hint,
      has_api_key: Boolean(u.encrypted_api_key)
    },
    logs: logs || []
  });
});

// --- USER SETTINGS (Save Encrypted API Key & Studio Lite IDs) ---
app.post('/api/settings', requireAuth, rateLimit(15, 60 * 1000), async (req, res) => {
  const robloxUserId = String(req.body.robloxUserId || '').replace(/\D/g, '');
  const robloxUniverseId = String(req.body.robloxUniverseId || '').replace(/\D/g, '');
  const robloxPlaceId = String(req.body.robloxPlaceId || '').replace(/\D/g, '');
  const rawApiKey = String(req.body.apiKey || '').trim();

  const updates = {
    roblox_user_id: robloxUserId,
    roblox_universe_id: robloxUniverseId,
    roblox_place_id: robloxPlaceId
  };

  if (rawApiKey) {
    if (rawApiKey.length < 20) {
      return res.status(400).json({ error: 'Format Open Cloud API Key tidak valid.' });
    }
    updates.encrypted_api_key = encryptApiKey(rawApiKey);
    updates.api_key_hint = `${rawApiKey.slice(0, 6)}...${rawApiKey.slice(-4)}`;
  }

  const { error } = await supabase.from('users').update(updates).eq('id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });

  res.json({
    success: true,
    api_key_hint: updates.api_key_hint || req.user.api_key_hint,
    roblox_user_id: robloxUserId,
    roblox_universe_id: robloxUniverseId,
    roblox_place_id: robloxPlaceId
  });
});

// --- ADMIN ROUTES (ADMINHCO ONLY) ---
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('id, username, role, credits, free_rbxl_vouchers, free_rbxm_vouchers, roblox_user_id, api_key_hint, created_at')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ users });
});

app.post('/api/admin/reward', requireAuth, requireAdmin, async (req, res) => {
  const { targetUserId, action, amount, voucherType } = req.body;
  const { data: target } = await supabase.from('users').select('*').eq('id', targetUserId).maybeSingle();
  if (!target) return res.status(404).json({ error: 'User tidak ditemukan.' });

  const updates = {};
  if (action === 'add_credits') {
    updates.credits = Math.max(0, target.credits + Number(amount || 0));
  } else if (action === 'set_credits') {
    updates.credits = Math.max(0, Number(amount || 0));
  } else if (action === 'give_voucher') {
    if (voucherType === 'rbxl') {
      updates.free_rbxl_vouchers = target.free_rbxl_vouchers + Math.max(1, Number(amount || 1));
    } else if (voucherType === 'rbxm') {
      updates.free_rbxm_vouchers = target.free_rbxm_vouchers + Math.max(1, Number(amount || 1));
    }
  }

  const { error } = await supabase.from('users').update(updates).eq('id', targetUserId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// --- UPLOAD & ROBLOX API LOGIC ---
const uploadDir = path.join(os.tmpdir(), 'studio-lite-uploads');
const upload = multer({
  storage: multer.diskStorage({
    destination: async (req, file, cb) => {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${crypto.randomUUID()}${ext}`);
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!['.rbxl', '.rbxlx', '.rbxm', '.rbxmx'].includes(ext)) {
      return cb(new Error('Hanya menerima file .rbxl, .rbxlx, .rbxm, atau .rbxmx'));
    }
    cb(null, true);
  }
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.post('/api/upload', requireAuth, rateLimit(8, 60 * 1000), upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Pilih file terlebih dahulu.' });

  const user = req.user;
  const inputPath = req.file.path;
  const ext = path.extname(req.file.originalname).toLowerCase();
  const isPlaceFile = ext === '.rbxl' || ext === '.rbxlx';
  const uploadTarget = req.body.uploadTarget === 'place_id' ? 'place_id' : 'model_id';
  const mode = req.body.mode === 'full' ? 'full' : 'workspace';
  const stripMedia = req.body.stripMedia !== 'false' ? 'true' : 'false';
  const displayName = String(req.body.displayName || path.basename(req.file.originalname, ext)).trim().slice(0, 50) || 'StudioLiteMap';

  let convertedPath = null;

  try {
    if (!user.encrypted_api_key) {
      throw new Error('Anda belum mengatur Open Cloud API Key di menu Pengaturan.');
    }
    const apiKey = decryptApiKey(user.encrypted_api_key);

    // Validasi Magic Bytes File Roblox (<roblox! atau <roblox )
    const rawBuf = await fs.readFile(inputPath);
    const headerStr = rawBuf.subarray(0, 16).toString('utf8');
    if (!headerStr.startsWith('<roblox')) {
      throw new Error('File ditolak sistem keamanan: Bukan file biner/XML Roblox (.rbxl/.rbxm) yang valid.');
    }

    // Hitung Credit atau Voucher Gratis
    const creditCost = calculateCreditCost(ext, req.file.size);
    let useVoucher = false;
    let voucherField = isPlaceFile ? 'free_rbxl_vouchers' : 'free_rbxm_vouchers';

    if (user[voucherField] > 0) {
      useVoucher = true;
    } else if (user.credits < creditCost) {
      throw new Error(`Credit tidak mencukupi. File ini membutuhkan ${creditCost} Credit (Saldo Anda: ${user.credits} Credit). Hubungi Admin ADMINHCO.`);
    }

    let resultId = '';
    let isPublic = false;
    let warningMsg = null;

    if (uploadTarget === 'place_id') {
      // METODE 1: STUDIO LITE VIA UNCOPYLOCK PLACE ID (Tanpa Verifikasi Creator Store!)
      if (!isPlaceFile) {
        throw new Error('Mode Place ID Bypass hanya untuk file .rbxl atau .rbxlx. Gunakan Mode Model Asset ID untuk .rbxm.');
      }
      if (!user.roblox_universe_id || !user.roblox_place_id) {
        throw new Error('Masukkan Universe ID dan Place ID terlebih dahulu di menu Pengaturan untuk menggunakan Mode Place ID Studio Lite.');
      }

      const contentType = ext === '.rbxlx' ? 'application/xml' : 'application/octet-stream';
      const placeRes = await fetch(
        `https://apis.roblox.com/universes/v1/${user.roblox_universe_id}/places/${user.roblox_place_id}/versions?versionType=Published`,
        {
          method: 'POST',
          headers: {
            'x-api-key': apiKey,
            'Content-Type': contentType
          },
          body: rawBuf
        }
      );

      const placeData = await placeRes.json().catch(() => ({}));
      if (!placeRes.ok) {
        throw new Error(`Place Publishing API Error (${placeRes.status}): ${placeData.message || JSON.stringify(placeData)}`);
      }

      resultId = user.roblox_place_id;
      isPublic = true;
    } else {
      // METODE 2: MODEL ASSET ID (Assets API + Creator Store)
      if (!user.roblox_user_id) {
        throw new Error('Masukkan Roblox User ID Anda di menu Pengaturan terlebih dahulu.');
      }

      let finalRbxmPath = inputPath;
      if (ext !== '.rbxm' || stripMedia === 'true') {
        const luneBin = await getLuneBinary();
        convertedPath = path.join(uploadDir, `${crypto.randomUUID()}.rbxm`);
        await execFileAsync(luneBin, [
          'run',
          path.join(__dirname, '..', 'convert.luau'),
          inputPath,
          convertedPath,
          mode,
          displayName,
          stripMedia
        ]);
        finalRbxmPath = convertedPath;
      }

      const rbxmBuf = await fs.readFile(finalRbxmPath);
      if (rbxmBuf.length > 20 * 1024 * 1024) {
        throw new Error('Ukuran hasil konversi .rbxm melebihi batas 20 MB Open Cloud API.');
      }

      const form = new FormData();
      form.append(
        'request',
        JSON.stringify({
          assetType: 'Model',
          displayName,
          description: 'Uploaded for Studio Lite',
          creationContext: { creator: { userId: String(user.roblox_user_id) } }
        })
      );
      form.append('fileContent', new Blob([rbxmBuf], { type: 'model/x-rbxm' }), 'model.rbxm');

      const uploadRes = await fetch('https://apis.roblox.com/assets/v1/assets', {
        method: 'POST',
        headers: { 'x-api-key': apiKey },
        body: form
      });
      const uploadData = await uploadRes.json().catch(() => ({}));
      if (!uploadRes.ok) {
        throw new Error(`Assets API Error (${uploadRes.status}): ${uploadData.message || JSON.stringify(uploadData)}`);
      }

      const opId = uploadData.operationId || uploadData.path?.split('/').pop();
      for (let i = 0; i < 25; i++) {
        await sleep(2000);
        const opRes = await fetch(`https://apis.roblox.com/assets/v1/operations/${opId}`, {
          headers: { 'x-api-key': apiKey }
        });
        const opData = await opRes.json().catch(() => ({}));
        if (opData.done) {
          if (opData.error) throw new Error(opData.error.message || 'Gagal memproses aset di server Roblox.');
          resultId = String(opData.response?.assetId || opData.response?.path?.split('/').pop());
          break;
        }
      }
      if (!resultId) throw new Error('Timeout menunggu pembuatan Asset ID dari Roblox.');

      // Coba publikasikan ke Creator Store
      const storeRes = await fetch('https://apis.roblox.com/cloud/v2/creator-store-products', {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          modelAssetId: resultId,
          published: true,
          basePrice: { currencyCode: 'USD', quantity: { significand: 0, exponent: -9 } }
        })
      });
      const storeData = await storeRes.json().catch(() => ({}));
      if (storeRes.ok) {
        isPublic = true;
      } else {
        warningMsg = `Model ID dibuat (${resultId}), tetapi Creator Store menolak publikasi otomatis: ${storeData.message || storeRes.status}. Gunakan "Mode Studio Lite Place ID Bypass" jika akun Anda belum lolos verifikasi Creator Store!`;
      }
    }

    // Potong Credit atau Voucher setelah sukses
    const userUpdates = {};
    if (useVoucher) {
      userUpdates[voucherField] = Math.max(0, user[voucherField] - 1);
    } else {
      userUpdates.credits = Math.max(0, user.credits - creditCost);
    }
    await supabase.from('users').update(userUpdates).eq('id', user.id);

    await supabase.from('upload_logs').insert({
      user_id: user.id,
      username: user.username,
      file_name: req.file.originalname,
      file_type: ext,
      file_size_bytes: req.file.size,
      upload_mode: uploadTarget,
      result_id: resultId,
      is_public: isPublic,
      credit_used: useVoucher ? 0 : creditCost,
      used_voucher: useVoucher
    });

    res.json({
      success: true,
      resultId,
      uploadTarget,
      isPublic,
      warningMsg,
      creditUsed: useVoucher ? 0 : creditCost,
      usedVoucher: useVoucher
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  } finally {
    await fs.unlink(inputPath).catch(() => {});
    if (convertedPath) await fs.unlink(convertedPath).catch(() => {});
  }
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));
}

module.exports = app;