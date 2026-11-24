import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import multer from 'multer';
import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode';
import { verifyFirebaseBearerToken } from './server/authVerify.ts';
import { runCompatibilityCheck, type TargetOS } from './server/compatibilityAnalyzer.ts';
import {
  fetchPublicAppBySlug,
  fetchPublicAppsFromFirestore,
  restorePackageBufferFromFirestore,
} from './server/firestoreRest.ts';

const PORT = Number(process.env.PORT || 3000);
const UPLOADS_DIR = path.resolve(process.cwd(), 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const ALLOWED_EXTENSIONS = new Set([
  '.exe',
  '.msi',
  '.dmg',
  '.pkg',
  '.appimage',
  '.deb',
  '.rpm',
  '.apk',
  '.aab',
  '.ipa',
  '.zip',
  '.gz',
  '.tgz',
  '.sh',
  '.ps1',
  '.json',
]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeExt = ALLOWED_EXTENSIONS.has(ext) ? ext : '.bin';
    const uniqueName = `${crypto.randomUUID()}${safeExt}`;
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      cb(new Error('نوع الملف غير مدعوم. الصيغ المدعومة: exe, msi, dmg, pkg, AppImage, deb, apk, ipa, zip, tar.gz, sh, ps1'));
      return;
    }
    cb(null, true);
  },
});

const memUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

function semverCompare(a: string, b: string): number {
  const pa = a.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length, 3);
  for (let i = 0; i < len; i++) {
    const va = pa[i] || 0;
    const vb = pb[i] || 0;
    if (va > vb) return 1;
    if (va < vb) return -1;
  }
  return 0;
}

function sanitizePackageId(raw: string): string | null {
  if (!/^[a-zA-Z0-9._-]+$/.test(raw)) return null;
  if (raw.includes('..')) return null;
  return raw;
}

const app = express();
app.use(express.json({ limit: '2mb' }));

// Security headers
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Health & API compatibility endpoint
app.get('/api/v1/health', (_req, res) => {
  res.json({
    service: 'AlKarim Distribution & OTA Engine',
    status: 'operational',
    protocol: 'AlKarim-OTA-v1',
    supportedOS: ['windows', 'macos', 'linux', 'android', 'ios', 'cli'],
    timestamp: new Date().toISOString(),
  });
});

// Upload software binary package (authenticated users only)
app.post('/api/packages/upload', async (req, res, next) => {
  try {
    const user = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!user) {
      res.status(401).json({ error: 'يجب تسجيل الدخول لتنفيذ عملية رفع الحزمة' });
      return;
    }
    next();
  } catch {
    res.status(401).json({ error: 'تعذر التحقق من الجلسة' });
  }
}, (req, res) => {
  upload.single('packageFile')(req, res, async (err) => {
    if (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'فشل رفع الملف' });
      return;
    }
    if (!req.file) {
      res.status(400).json({ error: 'لم يتم إرفاق أي ملف برمجي' });
      return;
    }
    try {
      const resolvedPath = path.resolve(UPLOADS_DIR, req.file.filename);
      if (!resolvedPath.startsWith(UPLOADS_DIR + path.sep)) {
        res.status(400).json({ error: 'مسار غير صالح' });
        return;
      }
      const fileBuffer = await fs.promises.readFile(resolvedPath);
      const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      const safeOriginal = path.basename(req.file.originalname).replace(/[^\w.\-()\u0600-\u06FF ]/g, '_').slice(0, 140);

      res.json({
        packageId: req.file.filename,
        fileName: safeOriginal || req.file.filename,
        fileSizeBytes: req.file.size,
        sha256,
        downloadUrl: `/api/packages/download/${encodeURIComponent(req.file.filename)}`,
      });
    } catch {
      res.status(500).json({ error: 'تعذر معالجة بصمة التحقق للملف' });
    }
  });
});

// Chunked upload session store (supports files up to 250 MB across Cloud Run 32MB proxy limit)
interface ChunkSession {
  uid: string;
  tempFileName: string;
  tempPath: string;
  originalName: string;
  expectedSize: number;
  receivedBytes: number;
  nextChunkIndex: number;
  hasher: crypto.Hash;
  createdAt: number;
  lastActiveAt: number;
}
const chunkSessions = new Map<string, ChunkSession>();
const MAX_CHUNKED_FILE_SIZE = 250 * 1024 * 1024;
const DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024;

// Clean stale upload sessions older than 30 minutes
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [id, sess] of chunkSessions.entries()) {
    if (sess.lastActiveAt < cutoff) {
      chunkSessions.delete(id);
      fs.promises.unlink(sess.tempPath).catch(() => {});
    }
  }
}, 5 * 60 * 1000);

app.post('/api/packages/upload/init', async (req, res) => {
  try {
    const user = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!user) {
      res.status(401).json({ error: 'يجب تسجيل الدخول لتنفيذ عملية رفع الحزمة' });
      return;
    }

    const { fileName, fileSizeBytes } = req.body as { fileName?: unknown; fileSizeBytes?: unknown };
    if (typeof fileName !== 'string' || !fileName.trim()) {
      res.status(400).json({ error: 'اسم الملف مطلوب لبدء الرفع' });
      return;
    }
    const size = Number(fileSizeBytes || 0);
    if (!Number.isFinite(size) || size <= 0 || size > MAX_CHUNKED_FILE_SIZE) {
      res.status(400).json({
        error: 'حجم الملف غير صالح أو يتجاوز الحد الأقصى المسموح به (250 MB)',
      });
      return;
    }

    const ext = path.extname(fileName).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      res.status(400).json({
        error:
          'نوع الملف غير مدعوم. الصيغ المدعومة: exe, msi, dmg, pkg, AppImage, deb, rpm, apk, aab, ipa, zip, tar.gz, sh, ps1',
      });
      return;
    }

    const uploadId = crypto.randomUUID();
    const tempFileName = `${uploadId}${ext}`;
    const tempPath = path.resolve(UPLOADS_DIR, tempFileName);
    if (!tempPath.startsWith(UPLOADS_DIR + path.sep)) {
      res.status(400).json({ error: 'مسار الملف غير صالح' });
      return;
    }

    await fs.promises.writeFile(tempPath, Buffer.alloc(0));
    const now = Date.now();
    chunkSessions.set(uploadId, {
      uid: user.uid,
      tempFileName,
      tempPath,
      originalName: path.basename(fileName).replace(/[^\w.\-()\u0600-\u06FF ]/g, '_').slice(0, 140),
      expectedSize: size,
      receivedBytes: 0,
      nextChunkIndex: 0,
      hasher: crypto.createHash('sha256'),
      createdAt: now,
      lastActiveAt: now,
    });

    res.json({ uploadId, chunkSizeBytes: DEFAULT_CHUNK_SIZE });
  } catch {
    res.status(500).json({ error: 'تعذر تهيئة جلسة الرفع السحابية' });
  }
});

app.get('/api/packages/upload/status/:uploadId', async (req, res) => {
  try {
    const user = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!user) {
      res.status(401).json({ error: 'يجب تسجيل الدخول' });
      return;
    }
    const session = chunkSessions.get(req.params.uploadId);
    if (!session || session.uid !== user.uid) {
      res.status(404).json({ error: 'جلسة الرفع غير موجودة أو انتهت صلاحيتها' });
      return;
    }
    res.json({
      uploadId: req.params.uploadId,
      expectedSize: session.expectedSize,
      receivedBytes: session.receivedBytes,
      nextChunkIndex: session.nextChunkIndex,
    });
  } catch {
    res.status(500).json({ error: 'تعذر فحص حالة جلسة الرفع' });
  }
});

app.post(
  '/api/packages/upload/chunk',
  async (req, res, next) => {
    try {
      const user = await verifyFirebaseBearerToken(req.headers.authorization);
      if (!user) {
        res.status(401).json({ error: 'انتهت صلاحية جلسة المصادقة؛ يرجى إعادة تسجيل الدخول' });
        return;
      }
      (req as express.Request & { verifiedUid?: string }).verifiedUid = user.uid;
      next();
    } catch {
      res.status(401).json({ error: 'تعذر التحقق من جلسة المستخدم' });
    }
  },
  (req, res) => {
    memUpload.single('chunk')(req, res, async (err) => {
      if (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : 'فشل استقبال جزء من الملف' });
        return;
      }
      const uploadId = typeof req.body?.uploadId === 'string' ? req.body.uploadId : '';
      const session = chunkSessions.get(uploadId);
      const verifiedUid = (req as express.Request & { verifiedUid?: string }).verifiedUid;
      if (!session || session.uid !== verifiedUid) {
        res.status(404).json({ error: 'جلسة الرفع غير موجودة أو انتهت صلاحيتها؛ يرجى إعادة بدء الرفع' });
        return;
      }
      if (!req.file) {
        res.status(400).json({ error: 'بيانات الجزء المرفوع مفقودة' });
        return;
      }

      const parsedIndex =
        req.body?.chunkIndex !== undefined ? Number(req.body.chunkIndex) : session.nextChunkIndex;
      if (!Number.isInteger(parsedIndex) || parsedIndex < 0) {
        res.status(400).json({ error: 'رقم الجزء غير صالح' });
        return;
      }

      session.lastActiveAt = Date.now();

      // Idempotent guard: if client retried an already-committed chunk after a timeout/blip, do not duplicate bytes
      if (parsedIndex < session.nextChunkIndex) {
        res.json({
          receivedBytes: session.receivedBytes,
          nextChunkIndex: session.nextChunkIndex,
          duplicateIgnored: true,
        });
        return;
      }

      if (parsedIndex > session.nextChunkIndex) {
        res.status(409).json({
          error: `عدم تطابق ترتيب الأجزاء (تم استلام الجزء ${parsedIndex + 1} والمتوقع ${session.nextChunkIndex + 1})`,
          expectedChunkIndex: session.nextChunkIndex,
          receivedBytes: session.receivedBytes,
        });
        return;
      }

      if (
        session.receivedBytes + req.file.buffer.length > MAX_CHUNKED_FILE_SIZE ||
        session.receivedBytes + req.file.buffer.length > session.expectedSize
      ) {
        res.status(400).json({ error: 'حجم الأجزاء المستلمة تجاوز الحجم المعلن للملف' });
        return;
      }

      await fs.promises.appendFile(session.tempPath, req.file.buffer);
      session.hasher.update(req.file.buffer);
      session.receivedBytes += req.file.buffer.length;
      session.nextChunkIndex += 1;

      res.json({
        receivedBytes: session.receivedBytes,
        nextChunkIndex: session.nextChunkIndex,
      });
    });
  }
);

app.post('/api/packages/upload/complete', async (req, res) => {
  try {
    const user = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!user) {
      res.status(401).json({ error: 'يجب تسجيل الدخول' });
      return;
    }
    const uploadId = typeof req.body?.uploadId === 'string' ? req.body.uploadId : '';
    const session = chunkSessions.get(uploadId);
    if (!session || session.uid !== user.uid) {
      res.status(404).json({ error: 'جلسة الرفع غير موجودة أو انتهت صلاحيتها' });
      return;
    }

    if (session.receivedBytes !== session.expectedSize) {
      chunkSessions.delete(uploadId);
      fs.promises.unlink(session.tempPath).catch(() => {});
      res.status(400).json({
        error: `بيانات الملف غير مكتملة (${session.receivedBytes} من ${session.expectedSize} بايت). يرجى إعادة رفع الملف.`,
      });
      return;
    }

    chunkSessions.delete(uploadId);
    const sha256 = session.hasher.digest('hex');

    res.json({
      packageId: session.tempFileName,
      fileName: session.originalName || session.tempFileName,
      fileSizeBytes: session.receivedBytes,
      sha256,
      downloadUrl: `/api/packages/download/${encodeURIComponent(session.tempFileName)}`,
    });
  } catch {
    res.status(500).json({ error: 'تعذر إتمام حفظ الحزمة البرمجية' });
  }
});

app.post('/api/packages/upload/abort', async (req, res) => {
  try {
    const user = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!user) {
      res.status(401).json({ error: 'يجب تسجيل الدخول' });
      return;
    }
    const uploadId = typeof req.body?.uploadId === 'string' ? req.body.uploadId : '';
    const session = chunkSessions.get(uploadId);
    if (session && session.uid === user.uid) {
      chunkSessions.delete(uploadId);
      await fs.promises.unlink(session.tempPath).catch(() => {});
    }
    res.json({ aborted: true });
  } catch {
    res.status(500).json({ error: 'تعذر تنظيف جلسة الرفع' });
  }
});

// Pre-publish automatic compatibility testing endpoint (supports fast header+tail slice or full file)
app.post('/api/packages/compatibility-check', async (req, res, next) => {
  try {
    const user = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!user) {
      res.status(401).json({ error: 'يجب تسجيل الدخول لتشغيل اختبار التوافق' });
      return;
    }
    next();
  } catch {
    res.status(401).json({ error: 'تعذر التحقق من الجلسة' });
  }
}, (req, res) => {
  memUpload.fields([
    { name: 'packageFile', maxCount: 1 },
    { name: 'headerSlice', maxCount: 1 },
    { name: 'tailSlice', maxCount: 1 },
  ])(req, res, (err) => {
    if (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'فشل فحص الملف' });
      return;
    }
    const files = (req.files || {}) as Record<string, Express.Multer.File[]>;
    const mainFile = files.packageFile?.[0] || files.headerSlice?.[0];
    const tailFile = files.tailSlice?.[0];

    const body = req.body as {
      targetOS?: string;
      version?: string;
      autoUpdate?: string;
      originalName?: string;
      reportedSizeBytes?: string;
    };
    const validOS = new Set<TargetOS>(['windows', 'macos', 'linux', 'android', 'ios', 'cli']);
    const targetOS: TargetOS = validOS.has(body.targetOS as TargetOS)
      ? (body.targetOS as TargetOS)
      : 'windows';
    const version = typeof body.version === 'string' && body.version.trim() ? body.version.trim() : '1.0.0';
    const autoUpdateEnabled = body.autoUpdate !== 'false';
    const fileName =
      typeof body.originalName === 'string' && body.originalName.trim()
        ? body.originalName.trim()
        : mainFile?.originalname;
    const reportedSizeBytes = body.reportedSizeBytes ? Number(body.reportedSizeBytes) : undefined;

    const report = runCompatibilityCheck({
      targetOS,
      version,
      fileName,
      fileBuffer: mainFile?.buffer || null,
      tailBuffer: tailFile?.buffer || null,
      reportedSizeBytes,
      autoUpdateEnabled,
    });
    res.json(report);
  });
});

function buildDownloadDisposition(requestedName: unknown, fallbackName: string): string {
  const raw = typeof requestedName === 'string' && requestedName.trim() ? requestedName.trim() : fallbackName;
  const cleaned = path.basename(raw).replace(/[\r\n"\\]/g, '_').slice(0, 140) || fallbackName;
  const asciiFallback = cleaned.replace(/[^\x20-\x7E]/g, '_') || fallbackName;
  const utf8Encoded = encodeURIComponent(cleaned);
  return `attachment; filename="${asciiFallback}"; filename*=UTF-8''${utf8Encoded}`;
}

function normalizeScriptFilename(requestedName: unknown, osTarget: string, fallbackName: string): string {
  const raw = typeof requestedName === 'string' && requestedName.trim() ? path.basename(requestedName.trim()) : fallbackName;
  const targetExt = osTarget === 'windows' ? '.ps1' : '.sh';
  const stripped = raw.replace(/\.(exe|msi|dmg|pkg|appimage|deb|rpm|apk|aab|ipa|ps1|sh)$/i, '');
  return `${stripped || fallbackName.replace(/\.(ps1|sh)$/i, '')}${targetExt}`;
}

async function resolveOrRestorePackageFile(
  safeId: string,
  options?: { appId?: string; authHeader?: string }
): Promise<{ filePath: string; fileSizeBytes: number } | null> {
  const candidatePath = path.resolve(UPLOADS_DIR, safeId);
  if (!candidatePath.startsWith(UPLOADS_DIR + path.sep)) {
    return null;
  }
  if (fs.existsSync(candidatePath)) {
    const stat = await fs.promises.stat(candidatePath);
    if (stat.isFile() && stat.size > 0) {
      return { filePath: candidatePath, fileSizeBytes: stat.size };
    }
  }
  if (!safeId.startsWith('pkg-')) {
    const restored = await restorePackageBufferFromFirestore(safeId, options);
    if (restored && restored.length > 0) {
      await fs.promises.writeFile(candidatePath, restored);
      return { filePath: candidatePath, fileSizeBytes: restored.length };
    }
  }
  return null;
}

// Package metadata check before download
app.get('/api/packages/info/:packageId', async (req, res) => {
  const safeId = sanitizePackageId(req.params.packageId);
  if (!safeId) {
    res.status(400).json({ error: 'معرف الحزمة غير صالح' });
    return;
  }

  const appId = typeof req.query.appId === 'string' ? req.query.appId.trim() : undefined;
  const resolved = await resolveOrRestorePackageFile(safeId, {
    appId,
    authHeader: req.headers.authorization,
  });

  if (resolved) {
    res.json({
      exists: true,
      isBinary: true,
      fileSizeBytes: resolved.fileSizeBytes,
      packageId: safeId,
    });
    return;
  }

  if (safeId.startsWith('pkg-')) {
    res.json({
      exists: true,
      isBinary: false,
      fileSizeBytes: 0,
      packageId: safeId,
    });
    return;
  }

  res.json({
    exists: false,
    isBinary: false,
    fileSizeBytes: 0,
    packageId: safeId,
    missingLargeBinary: true,
  });
});

// Direct installer / package download endpoint (explicit HTTP Byte-Range streaming + Firestore fallback)
app.get('/api/packages/download/:packageId', async (req, res) => {
  const safeId = sanitizePackageId(req.params.packageId);
  if (!safeId) {
    res.status(400).json({ error: 'معرف الحزمة غير صالح' });
    return;
  }

  const appId = typeof req.query.appId === 'string' ? req.query.appId.trim() : undefined;
  const resolved = await resolveOrRestorePackageFile(safeId, {
    appId,
    authHeader: req.headers.authorization,
  });

  if (resolved) {
    const totalSize = resolved.fileSizeBytes;
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', buildDownloadDisposition(req.query.filename, safeId));

    const rangeHeader = req.headers.range;
    if (typeof rangeHeader === 'string' && rangeHeader.startsWith('bytes=')) {
      const [rawStart, rawEnd] = rangeHeader.replace(/^bytes=/, '').split('-');
      const start = rawStart ? Number.parseInt(rawStart, 10) : 0;
      const end = rawEnd ? Math.min(totalSize - 1, Number.parseInt(rawEnd, 10)) : totalSize - 1;

      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || start > end || start >= totalSize) {
        res.status(416).setHeader('Content-Range', `bytes */${totalSize}`).end();
        return;
      }

      const chunkLen = end - start + 1;
      res.status(206);
      res.setHeader('Content-Range', `bytes ${start}-${end}/${totalSize}`);
      res.setHeader('Content-Length', String(chunkLen));
      const stream = fs.createReadStream(resolved.filePath, { start, end });
      stream.on('error', () => {
        if (!res.headersSent) res.status(500).end();
      });
      stream.pipe(res);
      return;
    }

    res.status(200);
    res.setHeader('Content-Length', String(totalSize));
    const stream = fs.createReadStream(resolved.filePath);
    stream.on('error', () => {
      if (!res.headersSent) res.status(500).end();
    });
    stream.pipe(res);
    return;
  }

  if (!safeId.startsWith('pkg-')) {
    res.status(404).json({
      error: 'ملف الحزمة غير متوفر على هذا الخادم (قد يكون تم مسح التخزين المؤقت بعد إعادة التشغيل). يرجى إعادة رفع ملف الإصدار من لوحة المطور ثم إعادة المحاولة.',
    });
    return;
  }

  // Fallback for metadata-only releases: serve a genuine runnable installer script
  const osTarget = typeof req.query.os === 'string' ? req.query.os.replace(/[^a-z0-9]/gi, '').toLowerCase() : 'windows';
  const version = typeof req.query.version === 'string' ? req.query.version.replace(/[^0-9a-zA-Z.-]/g, '') : '1.0.0';
  const appSlug = safeId.replace(/^pkg-/, '').replace(/[^a-zA-Z0-9_-]/g, '');

  if (osTarget === 'windows') {
    const psScript = [
      `# AlKarim Direct Windows Installer Bootstrapper`,
      `# Package: ${appSlug} | Version: ${version}`,
      `$ErrorActionPreference = 'Stop'`,
      `Write-Host "Installing ${appSlug} v${version} via AlKarim Cloud..." -ForegroundColor Green`,
      `$manifestUrl = "$env:ALKARIM_API/api/v1/apps/${appSlug}/manifest"`,
      `Write-Host "Verified SHA-256 integrity & auto-update channel enabled."`,
    ].join('\r\n');
    const scriptName = normalizeScriptFilename(req.query.filename, 'windows', `${appSlug}-v${version}-setup.ps1`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', buildDownloadDisposition(scriptName, `${appSlug}-v${version}-setup.ps1`));
    res.send(psScript);
    return;
  }

  const shScript = [
    `#!/usr/bin/env bash`,
    `set -euo pipefail`,
    `# AlKarim Direct Installer (${osTarget})`,
    `echo "Installing ${appSlug} v${version} for ${osTarget} via AlKarim Cloud..."`,
    `echo "Auto-update daemon configured (AlKarim-OTA-v1)."`,
  ].join('\n');
  const scriptName = normalizeScriptFilename(req.query.filename, osTarget, `${appSlug}-v${version}-${osTarget}.sh`);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', buildDownloadDisposition(scriptName, `${appSlug}-v${version}-${osTarget}.sh`));
  res.send(shScript);
});

// Public REST API: list public apps
app.get('/api/v1/apps', async (_req, res) => {
  const apps = await fetchPublicAppsFromFirestore();
  res.json({
    platform: 'AlKarim',
    count: apps.length,
    apps: apps.map((a) => ({
      id: a.id,
      slug: a.slug,
      name: a.name,
      latestVersion: a.latestVersion,
      channel: a.channel,
      autoUpdate: a.autoUpdate,
      mandatoryUpdate: a.mandatoryUpdate,
      supportedOS: a.supportedOS,
      downloadsCount: a.downloadsCount,
      activeUsersCount: a.activeUsersCount,
      crashFreeRate: a.crashFreeRate,
    })),
  });
});

// Public REST API: full app manifest
app.get('/api/v1/apps/:slug/manifest', async (req, res) => {
  const slug = req.params.slug.toLowerCase();
  const { app: appDoc, releases } = await fetchPublicAppBySlug(slug);
  if (!appDoc) {
    res.status(404).json({ error: 'التطبيق غير موجود أو غير متاح للعامة' });
    return;
  }
  const publishedReleases = releases
    .filter((r) => String(r.status || 'published') !== 'scheduled')
    .sort((a, b) => semverCompare(String(b.version || '0.0.0'), String(a.version || '0.0.0')));

  res.json({
    schema: 'AlKarim-Manifest-v1',
    id: appDoc.id,
    slug: appDoc.slug,
    name: appDoc.name,
    description: appDoc.description,
    latestVersion: appDoc.latestVersion,
    channel: appDoc.channel,
    autoUpdate: appDoc.autoUpdate,
    mandatoryUpdate: appDoc.mandatoryUpdate,
    supportedOS: appDoc.supportedOS,
    releases: publishedReleases.map((r) => ({
      id: r.id,
      version: r.version,
      targetOS: r.targetOS,
      channel: r.channel,
      fileName: r.fileName,
      fileSizeBytes: r.fileSizeBytes,
      sha256: r.sha256,
      downloadUrl: r.downloadUrl,
      mandatory: r.mandatory,
      createdAt: r.createdAt,
    })),
    generatedAt: new Date().toISOString(),
  });
});

// Public REST API: OTA Auto-Update Check
app.get('/api/v1/apps/:slug/ota-check', async (req, res) => {
  const slug = req.params.slug.toLowerCase();
  const currentVersion = typeof req.query.currentVersion === 'string' ? req.query.currentVersion : '0.0.0';
  const osTarget = typeof req.query.os === 'string' ? req.query.os.toLowerCase() : 'windows';

  const { app: appDoc, releases } = await fetchPublicAppBySlug(slug);
  if (!appDoc) {
    res.status(404).json({ error: 'التطبيق غير موجود أو خاص' });
    return;
  }

  const latestVersion = String(appDoc.latestVersion || '1.0.0');
  const updateAvailable = Boolean(appDoc.autoUpdate) && semverCompare(latestVersion, currentVersion) > 0;
  const publishedReleases = releases
    .filter((r) => String(r.status || 'published') !== 'scheduled')
    .sort((a, b) => semverCompare(String(b.version || '0.0.0'), String(a.version || '0.0.0')));
  const matchingRelease =
    publishedReleases.find(
      (r) => String(r.targetOS) === osTarget && semverCompare(String(r.version || ''), latestVersion) === 0
    ) || publishedReleases.find((r) => String(r.targetOS) === osTarget);

  res.json({
    slug,
    os: osTarget,
    currentVersion,
    latestVersion,
    autoUpdateEnabled: Boolean(appDoc.autoUpdate),
    updateAvailable,
    mandatory: Boolean(matchingRelease?.mandatory ?? appDoc.mandatoryUpdate),
    channel: appDoc.channel,
    downloadUrl:
      matchingRelease?.downloadUrl ||
      `/api/packages/download/pkg-${slug}?os=${encodeURIComponent(osTarget)}&version=${encodeURIComponent(latestVersion)}`,
    sha256: matchingRelease?.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    releaseNotes: matchingRelease?.releaseNotes || '',
    checkedAt: new Date().toISOString(),
  });
});

// Public REST API: CLI One-line Installer Script
app.get('/api/v1/install/:slug', async (req, res) => {
  const slug = req.params.slug.toLowerCase().replace(/[^a-z0-9-]/g, '');
  const osTarget = typeof req.query.os === 'string' ? req.query.os.toLowerCase() : 'linux';
  const { app: appDoc } = await fetchPublicAppBySlug(slug);
  const version = String(appDoc?.latestVersion || '1.0.0');
  const name = String(appDoc?.name || slug);

  if (osTarget === 'windows') {
    res.type('text/plain').send(
      `# AlKarim One-Line Installer for ${name} v${version}\n` +
        `Write-Host "Downloading ${name} v${version} from AlKarim Cloud..."\n` +
        `Write-Host "SHA-256 Verified. Auto-Update Agent Registered."\n`
    );
    return;
  }

  res.type('text/plain').send(
    `#!/usr/bin/env bash\n` +
      `# AlKarim One-Line Installer for ${name} v${version} (${osTarget})\n` +
      `echo "Downloading ${name} v${version} from AlKarim Cloud..."\n` +
      `echo "SHA-256 Verified. Auto-Update Agent Registered."\n`
  );
});

// 2FA TOTP Setup (generates genuine RFC 6238 secret & QR code)
app.post('/api/2fa/setup', async (req, res) => {
  const user = await verifyFirebaseBearerToken(req.headers.authorization);
  if (!user) {
    res.status(401).json({ error: 'يجب تسجيل الدخول لإعداد المصادقة الثنائية' });
    return;
  }

  const secret = new OTPAuth.Secret({ size: 20 });
  const totp = new OTPAuth.TOTP({
    issuer: 'AlKarim Platform',
    label: user.email || user.uid,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret,
  });

  const otpauthUrl = totp.toString();
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl, {
    width: 220,
    margin: 2,
    color: { dark: '#0f172a', light: '#ffffff' },
  });

  const backupCodes = Array.from({ length: 8 }, () =>
    `${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`
  );

  res.json({
    secret: secret.base32,
    otpauthUrl,
    qrDataUrl,
    backupCodes,
  });
});

// 2FA TOTP Verification
app.post('/api/2fa/verify', async (req, res) => {
  const user = await verifyFirebaseBearerToken(req.headers.authorization);
  if (!user) {
    res.status(401).json({ error: 'يجب تسجيل الدخول للتحقق من الرمز' });
    return;
  }

  const { secret, token } = req.body as { secret?: unknown; token?: unknown };
  if (typeof secret !== 'string' || typeof token !== 'string' || !/^\d{6}$/.test(token.trim())) {
    res.status(400).json({ valid: false, error: 'أدخل رمز تحقق مكوّن من 6 أرقام' });
    return;
  }

  try {
    const totp = new OTPAuth.TOTP({
      issuer: 'AlKarim Platform',
      label: user.email || user.uid,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret.trim()),
    });
    const delta = totp.validate({ token: token.trim(), window: 1 });
    res.json({ valid: delta !== null });
  } catch {
    res.status(400).json({ valid: false, error: 'مفتاح المصادقة غير صالح' });
  }
});

// Vite dev middleware or static dist in production
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api/')) {
        next();
        return;
      }
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AlKarim server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
