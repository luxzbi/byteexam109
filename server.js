'use strict';
require('dotenv').config();

const express    = require('express');
const path       = require('path');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const cors       = require('cors');
const { Pool }   = require('pg');

const app  = express();
const PORT = process.env.PORT || 4001;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PW   = process.env.ADMIN_PW;
if (!JWT_SECRET) { console.error('❌ JWT_SECRET 없음'); process.exit(1); }
if (!ADMIN_PW)   { console.error('❌ ADMIN_PW 없음');   process.exit(1); }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL DEFAULT '',
      pw TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      bio TEXT NOT NULL DEFAULT '',
      avatar TEXT NOT NULL DEFAULT '',
      banned BOOLEAN NOT NULL DEFAULT FALSE,
      banned_reason TEXT NOT NULL DEFAULT '',
      banned_at BIGINT,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS be_exams (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT '',
      difficulty TEXT NOT NULL DEFAULT '기본',
      extra TEXT NOT NULL DEFAULT '',
      content TEXT NOT NULL DEFAULT '',
      created_at BIGINT NOT NULL
    );
  `);
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1', ['studioztec']);
  if (!rows.length) {
    const hashed = await bcrypt.hash(ADMIN_PW, 12);
    await pool.query(
      'INSERT INTO users (id,username,display_name,pw,is_admin,bio,avatar,banned,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [uuid(), 'studioztec', '관리자', hashed, true, '', '', false, Date.now()]
    );
    console.log('✅ 관리자 계정 생성 완료');
  }
}

initDB().catch(e => { console.error('DB 초기화 실패', e); process.exit(1); });

const PUB = path.join(__dirname, 'public');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "blob:", "*.public.blob.vercel-storage.com"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      workerSrc: ["blob:"],
      fontSrc: ["'self'", "cdn.jsdelivr.net"]
    }
  }
}));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : true }));
app.use(express.json({ limit: '512kb' }));
app.use(express.static(PUB));
app.get('/lib/docx-preview.min.js', (req, res) =>
  res.sendFile(require('path').join(__dirname, 'node_modules/docx-preview/dist/docx-preview.min.js')));

const limiter        = rateLimit({ windowMs: 5*60*1000,  max: 300 });
const authLimiter    = rateLimit({ windowMs: 15*60*1000, max: 20,  message: { error: '너무 많은 시도입니다. 15분 후 다시 시도하세요.' } });
const registerLimiter = rateLimit({ windowMs: 60*60*1000, max: 10, message: { error: '회원가입 시도가 너무 많습니다. 1시간 후 다시 시도하세요.' } });
app.use('/api/', limiter);
app.use('/api/auth/login',    authLimiter);
app.use('/api/auth/register', registerLimiter);

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: '인증이 필요합니다.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    if (!req.user.id && req.user.sub) req.user.id = req.user.sub;
    next();
  } catch { res.status(401).json({ error: '만료되었거나 잘못된 토큰입니다.' }); }
}
async function adminOnly(req, res, next) {
  try {
    const { rows } = await pool.query('SELECT is_admin FROM users WHERE id=$1', [req.user.id]);
    if (!rows[0]?.is_admin) return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
    next();
  } catch { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
}

function mapUser(u) {
  if (!u) return null;
  return { id: u.id, _id: u.id, username: u.username, displayName: u.display_name, pw: u.pw, isAdmin: u.is_admin, createdAt: u.created_at };
}

app.get('/api/config', (req, res) => {
  res.json({ bytenodeUrl: process.env.BYTENODE_URL || 'https://bytenode109.vercel.app', siteName: 'byteexam' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, displayName, password } = req.body;
    if (!username || !displayName || !password)
      return res.status(400).json({ error: '아이디, 닉네임, 비밀번호를 모두 입력하세요.' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ error: '아이디는 영문·숫자·밑줄(_) 3~20자여야 합니다.' });
    if (String(displayName).trim().length < 2 || String(displayName).trim().length > 20)
      return res.status(400).json({ error: '닉네임은 2~20자여야 합니다.' });
    if (password.length < 6)
      return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });
    const { rows: existing } = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
    if (existing.length) return res.status(409).json({ error: '이미 사용 중인 아이디입니다.' });
    const hashed = await bcrypt.hash(password, 12);
    const id = uuid();
    const dn = String(displayName).trim();
    await pool.query(
      'INSERT INTO users (id,username,display_name,pw,is_admin,bio,avatar,banned,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [id, username, dn, hashed, false, '', '', false, Date.now()]
    );
    const token = jwt.sign({ id, username, displayName: dn, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ token, user: { id, username, displayName: dn, isAdmin: false } });
  } catch(e) { console.error('[register]', e); res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    const user = mapUser(rows[0]);
    if (!user) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
    const ok = await bcrypt.compare(password, user.pw);
    if (!ok) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
    const token = jwt.sign({ id: user.id, username: user.username, displayName: user.displayName, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, displayName: user.displayName, isAdmin: user.isAdmin } });
  } catch(e) { console.error('[login]', e); res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    const user = mapUser(rows[0]);
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    res.json({ id: user.id, username: user.username, displayName: user.displayName, isAdmin: user.isAdmin });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

const MAX_EXAMS = 30;

app.get('/api/exams', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM be_exams WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
    res.json(rows.map(e => ({ id: e.id, title: e.title, scope: e.scope, difficulty: e.difficulty, createdAt: e.created_at })));
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.get('/api/exams/:id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM be_exams WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: '시험지를 찾을 수 없습니다.' });
    const e = rows[0];
    res.json({ id: e.id, _id: e.id, userId: e.user_id, title: e.title, scope: e.scope, difficulty: e.difficulty, extra: e.extra, content: e.content, createdAt: e.created_at });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.post('/api/exams', auth, async (req, res) => {
  try {
    const { rows: [{ count }] } = await pool.query('SELECT COUNT(*) FROM be_exams WHERE user_id=$1', [req.user.id]);
    if (parseInt(count) >= MAX_EXAMS) return res.status(400).json({ error: `최대 ${MAX_EXAMS}개까지 저장 가능합니다.` });
    const { title, scope, difficulty, content, extra } = req.body;
    if (!title || !content) return res.status(400).json({ error: '제목과 내용을 입력하세요.' });
    const id = uuid();
    await pool.query(
      'INSERT INTO be_exams (id,user_id,title,scope,difficulty,extra,content,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, req.user.id, String(title).slice(0,120), String(scope||'').slice(0,200), String(difficulty||'기본').slice(0,50), String(extra||'').slice(0,500), String(content).slice(0,200000), Date.now()]
    );
    res.status(201).json({ id });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.patch('/api/exams/:id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM be_exams WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: '시험지를 찾을 수 없습니다.' });
    if (rows[0].user_id !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: '권한이 없습니다.' });
    const { title, scope, difficulty, content, extra } = req.body;
    const e = rows[0];
    await pool.query(
      'UPDATE be_exams SET title=$1,scope=$2,difficulty=$3,extra=$4,content=$5 WHERE id=$6',
      [title!==undefined?String(title).slice(0,120):e.title, scope!==undefined?String(scope).slice(0,200):e.scope, difficulty!==undefined?String(difficulty).slice(0,50):e.difficulty, extra!==undefined?String(extra).slice(0,500):e.extra, content!==undefined?String(content).slice(0,200000):e.content, e.id]
    );
    res.json({ ok: true });
  } catch(ex) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.delete('/api/exams/:id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM be_exams WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: '시험지를 찾을 수 없습니다.' });
    if (rows[0].user_id !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: '권한이 없습니다.' });
    await pool.query('DELETE FROM be_exams WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
    res.json(rows.map(u => ({ id: u.id, username: u.username, displayName: u.display_name, isAdmin: u.is_admin, createdAt: u.created_at })));
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: '자기 자신은 삭제할 수 없습니다.' });
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    await pool.query('DELETE FROM be_exams WHERE user_id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.patch('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const isAdmin = !!req.body.isAdmin;
    if (!isAdmin) {
      const { rows: [{ count }] } = await pool.query('SELECT COUNT(*) FROM users WHERE is_admin=true');
      if (parseInt(count) <= 1) return res.status(400).json({ error: '마지막 관리자의 권한은 해제할 수 없습니다.' });
    }
    await pool.query('UPDATE users SET is_admin=$1 WHERE id=$2', [isAdmin, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.get('/api/admin/exams', auth, adminOnly, async (req, res) => {
  try {
    const { rows: exams } = await pool.query('SELECT * FROM be_exams ORDER BY created_at DESC');
    const result = await Promise.all(exams.map(async e => {
      const { rows } = await pool.query('SELECT username,display_name FROM users WHERE id=$1', [e.user_id]);
      return { id: e.id, title: e.title, scope: e.scope, difficulty: e.difficulty, createdAt: e.created_at,
               username: rows[0]?.username||'(탈퇴)', displayName: rows[0]?.display_name||'(탈퇴)' };
    }));
    res.json(result);
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.delete('/api/admin/exams/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM be_exams WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const [{ rows: [{ count: uc }] }, { rows: [{ count: ec }] }] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM be_exams')
    ]);
    res.json({ userCount: parseInt(uc), examCount: parseInt(ec) });
  } catch(e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.get('/api/exams/:id/docx', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM be_exams WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: '시험지를 찾을 수 없습니다.' });
    const exam = rows[0];
    const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, AlignmentType, TableLayoutType } = require('docx');
    const TW = 10440;
    const content = exam.content || '';
    const startIdx = content.indexOf('---BYTEEXAM-START---');
    const endIdx   = content.indexOf('---BYTEEXAM-END---');
    const raw = startIdx !== -1 && endIdx !== -1 ? content.slice(startIdx + 20, endIdx) : content;
    const header = {}; const questions = []; let curQ = null;
    for (const line of raw.split('\n')) {
      const t2 = line.trim();
      if (!t2 || t2.startsWith('---')) continue;
      if (t2 === '[HEADER]') { curQ = null; continue; }
      if (t2 === '[QUESTION]') { curQ = {}; questions.push(curQ); continue; }
      const eq = t2.indexOf('='); if (eq < 0) continue;
      const k = t2.slice(0, eq).trim(), v = t2.slice(eq + 1).trim();
      if (!curQ) header[k] = v; else curQ[k] = v;
    }
    const title   = header.title      || exam.title     || '시험지';
    const subject = header.subject    || exam.scope      || '';
    const diff    = header.difficulty || exam.difficulty || '';
    const date    = header.date       || new Date().toLocaleDateString('ko-KR');
    const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
    const noBorder = { top: NONE, bottom: NONE, left: NONE, right: NONE };
    const thinBorder = { style: BorderStyle.SINGLE, size: 4, color: 'aaaaaa' };
    function t(text, opts = {}) { return new TextRun({ text: String(text || ''), font: '맑은 고딕', size: opts.size || 22, bold: !!opts.bold, color: opts.color || '111111' }); }
    function makeQParas(q) {
      const paras = [];
      const tp = q.type === 'short' ? '[단답형] ' : q.type === 'essay' ? '[서술형] ' : '';
      paras.push(new Paragraph({ spacing: { before: 80, after: 30 }, children: [t(`${q.num || ''}.`, { bold: true }), t('  ' + tp + (q.text || ''))] }));
      if (q.bogi_1 || q.bogi_2 || q.bogi_3) ['1','2','3'].forEach((n, i) => { if (q['bogi_'+n]) paras.push(new Paragraph({ indent: { left: 240 }, spacing: { before: 16, after: 16 }, children: [t('ㄱㄴㄷ'[i] + '. ' + q['bogi_'+n], { size: 20 })] })); });
      if (q.type && q.type.includes('choice')) { const sym = ['①','②','③','④','⑤']; ['1','2','3','4','5'].forEach((n, i) => { if (q['choice'+n]) paras.push(new Paragraph({ indent: { left: 200 }, spacing: { before: 18, after: 18 }, children: [t(sym[i] + ' ' + q['choice'+n], { size: 20 })] })); }); }
      if (q.point) paras.push(new Paragraph({ spacing: { before: 16, after: 50 }, children: [t(`[${q.point}점]`, { size: 18, color: '888888' })] }));
      return paras;
    }
    const half = Math.ceil(questions.length / 2);
    const headerTable = new Table({ width: { size: TW, type: WidthType.DXA }, layout: TableLayoutType.FIXED,
      borders: { top: { style: BorderStyle.THICK, size: 16, color: '111111' }, bottom: thinBorder, left: NONE, right: NONE, insideH: NONE, insideV: NONE },
      rows: [new TableRow({ children: [
        new TableCell({ width: { size: Math.round(TW*0.18), type: WidthType.DXA }, borders: noBorder, children: [new Paragraph({ children: [t('byteexam', { bold: true, size: 26, color: '6c63ff' })] }), new Paragraph({ children: [t('by cjy', { size: 16, color: '999999' })] })] }),
        new TableCell({ width: { size: Math.round(TW*0.58), type: WidthType.DXA }, borders: noBorder, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [t(title, { bold: true, size: 28 })] }), new Paragraph({ alignment: AlignmentType.CENTER, children: [t(subject + (diff ? ' | 난이도: ' + diff : ''), { size: 18, color: '555555' })] })] }),
        new TableCell({ width: { size: Math.round(TW*0.24), type: WidthType.DXA }, borders: noBorder, children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [t('이름: ___________', { size: 20 })] }), new Paragraph({ alignment: AlignmentType.RIGHT, children: [t('날짜: ' + date, { size: 20 })] })] })
      ]})] });
    const bodyTable = new Table({ width: { size: TW, type: WidthType.DXA }, layout: TableLayoutType.FIXED,
      borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideH: NONE, insideV: NONE },
      rows: [new TableRow({ children: [
        new TableCell({ width: { size: Math.round(TW*0.5), type: WidthType.DXA }, borders: { ...noBorder, right: thinBorder }, margins: { right: 216 }, children: questions.slice(0, half).flatMap(makeQParas) }),
        new TableCell({ width: { size: Math.round(TW*0.5), type: WidthType.DXA }, borders: noBorder, margins: { left: 216 }, children: questions.slice(half).flatMap(makeQParas) })
      ]})] });
    const ansRows = [new TableRow({ children: [new TableCell({ columnSpan: Math.min(questions.length, 10), borders: { top: { style: BorderStyle.DOUBLE, size: 6, color: '111111' }, bottom: NONE, left: NONE, right: NONE }, children: [new Paragraph({ spacing: { before: 200 }, children: [t('◆ 정답 및 해설', { bold: true, size: 22 })] })] })] })];
    for (let i = 0; i < questions.length; i += 10) {
      ansRows.push(new TableRow({ children: questions.slice(i, i+10).map(q => new TableCell({ borders: { top: thinBorder, bottom: thinBorder, left: thinBorder, right: thinBorder }, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [t(String(q.num||''), { bold: true, size: 18, color: '6c63ff' })] }), new Paragraph({ alignment: AlignmentType.CENTER, children: [t(q.answer_text||q.answer||'', { size: 18 })] })] })) }));
    }
    const explainParas = questions.filter(q=>q.explain).map(q => new Paragraph({ spacing: { before: 80 }, children: [t(`${q.num}번. `, { bold: true, size: 19 }), t(q.explain, { size: 19 })] }));
    const doc = new Document({ sections: [{ properties: { page: { margin: { top: 720, bottom: 720, left: 900, right: 900 } } }, children: [headerTable, new Paragraph({ spacing: { before: 120 } }), bodyTable, new Paragraph({ spacing: { before: 200 } }), new Table({ width: { size: TW, type: WidthType.DXA }, layout: TableLayoutType.FIXED, borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideH: NONE, insideV: NONE }, rows: ansRows }), ...explainParas] }] });
    const buf = await Packer.toBuffer(doc);
    const safeName = (exam.title || '시험지').replace(/[\\/:*?"<>|]/g, '_');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}.docx`);
    res.send(buf);
  } catch(e) { console.error('[docx]', e); res.status(500).json({ error: 'DOCX 생성 실패: ' + e.message }); }
});

app.get('/api/exams/:id/preview', (req, res, next) => {
  const token = req.query.token;
  if (!token) return res.status(401).send('<h2>인증이 필요합니다.</h2>');
  try { req.user = jwt.verify(token, JWT_SECRET); if (!req.user.id && req.user.sub) req.user.id = req.user.sub; next(); }
  catch { return res.status(401).send('<h2>토큰이 유효하지 않습니다.</h2>'); }
}, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM be_exams WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).send('<h2>시험지를 찾을 수 없습니다.</h2>');
    const exam = rows[0];
    const content = exam.content || '';
    const startIdx = content.indexOf('---BYTEEXAM-START---');
    const endIdx   = content.indexOf('---BYTEEXAM-END---');
    const raw = startIdx !== -1 && endIdx !== -1 ? content.slice(startIdx + 20, endIdx) : content;
    const header = {}; const questions = []; let curQ = null;
    for (const line of raw.split('\n')) {
      const t2 = line.trim();
      if (!t2 || t2.startsWith('---')) continue;
      if (t2 === '[HEADER]') { curQ = null; continue; }
      if (t2 === '[QUESTION]') { curQ = {}; questions.push(curQ); continue; }
      const eq = t2.indexOf('='); if (eq < 0) continue;
      const k = t2.slice(0, eq).trim(), v = t2.slice(eq + 1).trim();
      if (!curQ) header[k] = v; else curQ[k] = v;
    }
    const title   = header.title      || exam.title     || '시험지';
    const subject = header.subject    || exam.scope      || '';
    const diff    = header.difficulty || exam.difficulty || '';
    const date    = header.date       || new Date().toLocaleDateString('ko-KR');
    const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    function makeChoices(q) {
      const sym = ['①','②','③','④','⑤']; let html = '';
      if (q.bogi_1 || q.bogi_2 || q.bogi_3) { html += '<div style="margin:4px 0 4px 12px;font-size:11.5px">'; ['1','2','3'].forEach((n,i) => { if (q['bogi_'+n]) html += `<div>${['ㄱ','ㄴ','ㄷ'][i]}. ${esc(q['bogi_'+n])}</div>`; }); html += '</div>'; }
      if (q.type && q.type.includes('choice')) { html += '<div style="margin:4px 0 4px 12px;font-size:11.5px">'; ['1','2','3','4','5'].forEach((n,i) => { if (q['choice'+n]) html += `<div>${sym[i]} ${esc(q['choice'+n])}</div>`; }); html += '</div>'; }
      return html;
    }
    const typeLabel = { short:'[단답형] ', essay:'[서술형] ', '':'', undefined:'' };
    const half = Math.ceil(questions.length / 2);
    function renderQs(qs) { return qs.map(q => `<div style="margin-bottom:12px;break-inside:avoid"><div style="font-size:12.5px"><strong>${esc(q.num||'')}.</strong><span style="color:#555;font-size:11px">${esc(typeLabel[q.type]||'')}</span>${esc(q.text||'')}</div>${makeChoices(q)}${q.point?`<div style="font-size:10.5px;color:#999">[${esc(q.point)}점]</div>`:''}</div>`).join(''); }
    const answerRows = questions.map(q => `<td style="border:1px solid #ccc;padding:4px 8px;text-align:center;min-width:60px"><div style="color:#6c63ff;font-weight:700;font-size:11px">${esc(String(q.num||''))}</div><div style="font-size:11px">${esc(q.answer_text||q.answer||'')}</div></td>`).join('');
    const explainSection = questions.filter(q=>q.explain).map(q => `<div style="margin-bottom:8px;font-size:11.5px"><strong>${esc(q.num)}번.</strong> ${esc(q.explain)}</div>`).join('');
    const html = `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css" crossorigin="anonymous">
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js" crossorigin="anonymous"></script>
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/contrib/auto-render.min.js" crossorigin="anonymous" onload="renderMathInElement(document.body,{delimiters:[{left:'$$',right:'$$',display:true},{left:'$',right:'$',display:false},{left:'\\\\[',right:'\\\\]',display:true},{left:'\\\\(',right:'\\\\)',display:false}]})"></script>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Malgun Gothic','맑은 고딕',sans-serif;font-size:12px;background:#f4f4f4;color:#111}@media print{body{background:#fff}.no-print{display:none!important}}.page{background:#fff;max-width:800px;margin:0 auto;padding:28px 36px;min-height:100vh}.header{display:flex;justify-content:space-between;align-items:flex-start;border-top:3px solid #111;padding-top:10px;padding-bottom:10px;border-bottom:1px solid #ccc;margin-bottom:16px}.brand{font-size:16px;font-weight:800;color:#6c63ff}.brand-sub{font-size:10px;color:#999;margin-top:2px}.htitle{text-align:center;font-size:18px;font-weight:700}.hinfo{text-align:center;font-size:11px;color:#666;margin-top:3px}.hmeta{text-align:right;font-size:11px;line-height:1.8}.cols{display:grid;grid-template-columns:1fr 1fr;gap:0}.col-left{padding-right:16px;border-right:1px solid #ddd}.col-right{padding-left:16px}.ans-section{border-top:3px double #111;margin-top:24px;padding-top:12px}.toolbar{position:fixed;top:12px;right:16px;display:flex;gap:8px;z-index:999}.btn{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600}.btn-print{background:#6c63ff;color:#fff}</style></head>
<body><div class="toolbar no-print"><button class="btn btn-print" onclick="window.print()">🖨️ 인쇄/PDF저장</button></div>
<div class="page"><div class="header"><div><div class="brand">byteexam</div><div class="brand-sub">by cjy</div></div><div><div class="htitle">${esc(title)}</div><div class="hinfo">${esc(subject)}${diff?' | 난이도: '+esc(diff):''}</div></div><div class="hmeta"><div>이름: ___________</div><div>날짜: ${esc(date)}</div></div></div>
<div class="cols"><div class="col-left">${renderQs(questions.slice(0,half))}</div><div class="col-right">${renderQs(questions.slice(half))}</div></div>
${questions.length>0?`<div class="ans-section"><div style="font-weight:700;font-size:13px;margin-bottom:10px">◆ 정답 및 해설</div><table style="border-collapse:collapse;margin-bottom:12px"><tr>${answerRows}</tr></table>${explainSection}</div>`:''}
</div></body></html>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch(e) { console.error('[preview]', e); res.status(500).send('<h2>미리보기 생성 실패: ' + e.message + '</h2>'); }
});

app.get('*', (req, res) => res.sendFile(path.join(PUB, 'index.html')));

app.listen(PORT, () => console.log(`\n✅ byteexam 실행 중 → http://localhost:${PORT}\n`));
