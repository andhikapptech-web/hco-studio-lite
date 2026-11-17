require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const app = express();
const PORT = process.env.PORT || 3000;
const ROBLOX_API_KEY = process.env.ROBLOX_API_KEY;
const ROBLOX_USER_ID = process.env.ROBLOX_USER_ID;
const ROBLOX_GROUP_ID = process.env.ROBLOX_GROUP_ID;
const LUNE_PATH = process.env.LUNE_PATH || 'lune';

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // Maks. 50 MB file input mentah
const ROBLOX_ASSET_LIMIT_BYTES = 20 * 1024 * 1024; // Batas resmi Open Cloud Assets API: 20 MB

const uploadDir = path.join(os.tmpdir(), 'roblox-uploader-tmp');

const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (err) {
      cb(err);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (req, file, cb) => {
    const allowed = ['.rbxl', '.rbxlx', '.rbxm', '.rbxmx'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error('Format file tidak didukung. Gunakan .rbxl, .rbxlx, .rbxm, atau .rbxmx'));
    }
    cb(null, true);
  }
});

app.use(express.static(path.join(__dirname, 'public')));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function uploadToRobloxAssetsApi(rbxmBuffer, displayName, description) {
  const creator = ROBLOX_GROUP_ID
    ? { groupId: String(ROBLOX_GROUP_ID) }
    : { userId: String(ROBLOX_USER_ID) };

  const requestMetadata = {
    assetType: 'Model',
    displayName: displayName.slice(0, 50),
    description: (description || 'Uploaded via Web Asset Converter').slice(0, 1000),
    creationContext: { creator }
  };

  const form = new FormData();
  form.append('request', JSON.stringify(requestMetadata));
  // MIME type model/x-rbxm wajib agar parser Open Cloud Roblox membaca file .rbxm
  form.append('fileContent', new Blob([rbxmBuffer], { type: 'model/x-rbxm' }), 'model.rbxm');

  const res = await fetch('https://apis.roblox.com/assets/v1/assets', {
    method: 'POST',
    headers: {
      'x-api-key': ROBLOX_API_KEY
    },
    body: form
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Assets API Error (${res.status}): ${data.message || JSON.stringify(data)}`);
  }

  return data.operationId || data.path?.split('/').pop();
}

async function pollOperation(operationId) {
  const maxAttempts = 30;
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(2000);

    const res = await fetch(`https://apis.roblox.com/assets/v1/operations/${operationId}`, {
      headers: { 'x-api-key': ROBLOX_API_KEY }
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(`Operation Check Error (${res.status}): ${data.message || JSON.stringify(data)}`);
    }

    if (data.done) {
      if (data.error) {
        throw new Error(`Roblox gagal memproses aset: ${data.error.message || JSON.stringify(data.error)}`);
      }
      const assetId = data.response?.assetId || data.response?.path?.split('/').pop();
      if (!assetId) {
        throw new Error('Asset ID tidak ditemukan pada respons operasi Roblox.');
      }
      return String(assetId);
    }
  }

  throw new Error('Timeout menunggu server Roblox memproses file.');
}

async function publishToCreatorStoreFree(assetId) {
  const freePrice = {
    currencyCode: 'USD',
    quantity: {
      significand: 0,
      exponent: -9
    }
  };

  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    if (attempt > 1) await sleep(2500);

    // 1. Buat entri Creator Store Product baru
    const postRes = await fetch('https://apis.roblox.com/cloud/v2/creator-store-products', {
      method: 'POST',
      headers: {
        'x-api-key': ROBLOX_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        modelAssetId: String(assetId),
        published: true,
        basePrice: freePrice
      })
    });

    const postData = await postRes.json().catch(() => ({}));
    if (postRes.ok) {
      return { published: true, data: postData };
    }

    // 2. Hanya jalankan PATCH jika produk memang sudah ada (409 / already exists)
    if (postRes.status === 409 || String(postData.message || '').toLowerCase().includes('already')) {
      const patchRes = await fetch(
        `https://apis.roblox.com/cloud/v2/creator-store-products/${assetId}?updateMask=Published%2CBasePrice`,
        {
          method: 'PATCH',
          headers: {
            'x-api-key': ROBLOX_API_KEY,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            published: true,
            basePrice: freePrice
          })
        }
      );

      const patchData = await patchRes.json().catch(() => ({}));
      if (patchRes.ok) {
        return { published: true, data: patchData };
      }
      lastError = patchData.message || `HTTP ${patchRes.status}`;
      break;
    }

    lastError = postData.message || `HTTP ${postRes.status}`;

    // Jika error permanen (mis. syarat akun/aset tidak didukung), hentikan retry lebih cepat
    if (postRes.status === 400 || postRes.status === 403) {
      break;
    }
  }

  return { published: false, error: lastError };
}

app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (!ROBLOX_API_KEY || (!ROBLOX_USER_ID && !ROBLOX_GROUP_ID)) {
    return res.status(500).json({
      error: 'Konfigurasi server belum lengkap. Pastikan ROBLOX_API_KEY dan ROBLOX_USER_ID/ROBLOX_GROUP_ID diisi di .env'
    });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'File wajib diunggah.' });
  }

  const inputPath = req.file.path;
  const ext = path.extname(req.file.originalname).toLowerCase();
  const baseName =
    path.basename(req.file.originalname, ext).replace(/[^a-zA-Z0-9_\- ]/g, '').trim() || 'RobloxAsset';
  const displayName = (req.body.displayName || baseName).trim();
  const description = (req.body.description || 'Converted and uploaded via Web Asset Converter').trim();
  const mode = req.body.mode === 'full' ? 'full' : 'workspace';
  const stripMedia = req.body.stripMedia === 'true' ? 'true' : 'false';

  let convertedPath = null;

  try {
    let finalRbxmPath = inputPath;

    // Jalankan Lune untuk konversi .rbxl/.rbxlx/.rbxmx -> .rbxm, atau pembersihan Sound/VideoFrame
    if (ext !== '.rbxm' || stripMedia === 'true') {
      convertedPath = path.join(uploadDir, `${crypto.randomUUID()}.rbxm`);
      await execFileAsync(LUNE_PATH, [
        'run',
        path.join(__dirname, 'convert.luau'),
        inputPath,
        convertedPath,
        mode,
        displayName,
        stripMedia
      ]);
      finalRbxmPath = convertedPath;
    }

    const rbxmBuffer = await fs.readFile(finalRbxmPath);
    if (rbxmBuffer.length === 0) {
      throw new Error('Hasil konversi file kosong.');
    }
    if (rbxmBuffer.length > ROBLOX_ASSET_LIMIT_BYTES) {
      throw new Error(
        `Ukuran file .rbxm (${(rbxmBuffer.length / 1024 / 1024).toFixed(2)} MB) melebihi batas maksimal Roblox Open Cloud API (20 MB).`
      );
    }

    // 1. Unggah ke Open Cloud Assets API
    const operationId = await uploadToRobloxAssetsApi(rbxmBuffer, displayName, description);

    // 2. Tunggu hasil operasi
    const assetId = await pollOperation(operationId);

    // 3. Publikasikan gratis ke Creator Store agar bisa diakses semua orang
    const storeResult = await publishToCreatorStoreFree(assetId);

    res.json({
      success: true,
      assetId,
      displayName,
      isPublic: storeResult.published,
      publicWarning: storeResult.published
        ? null
        : `Aset berhasil diunggah (ID: ${assetId}), namun gagal dipublikasikan otomatis ke Creator Store: ${storeResult.error}. Cek halaman Konfigurasi Creator Hub untuk detail dependensi/izin akun.`,
      creatorStoreUrl: `https://create.roblox.com/store/asset/${assetId}`,
      dashboardUrl: `https://create.roblox.com/dashboard/creations/store/${assetId}/configure`
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: err.message || 'Terjadi kesalahan saat memproses file.' });
  } finally {
    await fs.unlink(inputPath).catch(() => {});
    if (convertedPath) {
      await fs.unlink(convertedPath).catch(() => {});
    }
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  if (err) {
    return res.status(400).json({ error: err.message });
  }
  next();
});

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});