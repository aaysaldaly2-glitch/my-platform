'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const PROD = process.env.NODE_ENV === 'production';
const { ADMIN_USER, ADMIN_PASS } = process.env;
if (!ADMIN_USER || !ADMIN_PASS || ADMIN_PASS.length < 12) {
  console.error('اضبط ADMIN_USER و ADMIN_PASS (12 حرفًا على الأقل) قبل التشغيل.');
  process.exit(1);
}

const db = new Database(path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student', active INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY, name TEXT NOT NULL, open INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS lessons(id INTEGER PRIMARY KEY, course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE, pos INTEGER NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL, homework TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY, lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, answer TEXT NOT NULL, grade INTEGER, feedback TEXT, created INTEGER NOT NULL, UNIQUE(lesson_id, user_id));
`);

const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const now = () => Date.now();
const str = (v, min, max) => typeof v === 'string' && v.trim().length >= min && v.length <= max;
const DUMMY = bcrypt.hashSync('dummy-password', 12); // يمنع كشف وجود المستخدم عبر زمن الاستجابة

if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  db.prepare('INSERT INTO users(username,hash,role,created) VALUES(?,?,?,?)')
    .run(ADMIN_USER.trim().toLowerCase(), bcrypt.hashSync(ADMIN_PASS, 12), 'admin', now());
}
if (!db.prepare('SELECT 1 FROM courses').get()) {
  const ic = db.prepare('INSERT INTO courses(name) VALUES(?)');
  ['Python', 'HTML', 'CSS', 'C++', 'Java', 'JavaScript', 'PHP'].forEach(n => ic.run(n));
}
if (!db.prepare('PRAGMA table_info(lessons)').all().some(c => c.name === 'course_id')) { // ترقية قاعدة بيانات قديمة
  db.exec('ALTER TABLE lessons ADD COLUMN course_id INTEGER');
  db.prepare("UPDATE lessons SET course_id = (SELECT id FROM courses WHERE name = 'C++')").run();
}
if (!db.prepare('SELECT 1 FROM lessons').get()) {
  const cpp = db.prepare("SELECT id FROM courses WHERE name = 'C++'").get().id;
  const ins = db.prepare('INSERT INTO lessons(course_id,pos,title,content,homework) VALUES(?,?,?,?,?)');
  ins.run(cpp, 1, 'الذاكرة والمؤشرات في C++',
    'الـ Stack يُدار تلقائيًا ويُحرَّر عند نهاية النطاق، أما الـ Heap فتديره أنت: كل new يقابله delete.\nالمؤشر (pointer) متغير يخزّن عنوان قيمة أخرى في الذاكرة.',
    'اكتب دالة تعكس مصفوفة أعداد صحيحة في مكانها (in-place) باستخدام مؤشرين، واشرح تعقيد الزمن والذاكرة.');
  ins.run(cpp, 2, 'تعقيد الخوارزميات Big-O',
    'Big-O يصف نمو زمن التنفيذ بزيادة حجم المدخلات. أمثلة: O(1) و O(log n) و O(n) و O(n log n) و O(n²).',
    'حلّل تعقيد البحث الثنائي والفرز بالدمج، ثم اكتب كود البحث الثنائي بلغتك المفضلة.');
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], objectSrc: ["'none'"], frameAncestors: ["'none'"],
      formAction: ["'self'"], baseUri: ["'self'"],
      upgradeInsecureRequests: PROD ? [] : null,
    },
  },
}));
app.use(express.json({ limit: '50kb' }));
app.use('/api', rateLimit({ windowMs: 60e3, limit: 120, standardHeaders: true, legacyHeaders: false }));
const authLimit = rateLimit({ windowMs: 15 * 60e3, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'محاولات كثيرة، حاول بعد 15 دقيقة.' } });

const ah = fn => (req, res, next) => fn(req, res, next).catch(next);
const cookie = (req, n) => (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(n + '='))?.slice(n.length + 1);

function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const csrf = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(sha(token), userId, csrf, now() + 8 * 3600e3);
  res.cookie('sid', token, { httpOnly: true, sameSite: 'strict', secure: PROD, maxAge: 8 * 3600e3, path: '/' });
  return csrf;
}
function auth(req, res, next) {
  const t = cookie(req, 'sid');
  const row = t && db.prepare('SELECT s.csrf, s.expires, u.id, u.username, u.role, u.active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').get(sha(t));
  if (!row || row.expires < now() || !row.active) return res.status(401).json({ error: 'سجّل الدخول أولًا.' });
  if (req.method !== 'GET' && req.get('x-csrf-token') !== row.csrf) return res.status(403).json({ error: 'طلب مرفوض.' });
  req.user = row;
  next();
}
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'للأدمن فقط.' });
const pub = u => ({ id: u.id, username: u.username, role: u.role });

app.post('/api/login', authLimit, ah(async (req, res) => {
  const { username, password } = req.body || {};
  if (!str(username, 3, 30) || !str(password, 1, 128)) return res.status(400).json({ error: 'بيانات غير صالحة.' });
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim().toLowerCase());
  const ok = await bcrypt.compare(password, u ? u.hash : DUMMY);
  if (!u || !ok || !u.active) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
  res.json({ user: pub(u), csrf: startSession(res, u.id) });
}));

app.post('/api/register', authLimit, ah(async (req, res) => {
  const { username, password } = req.body || {};
  const name = typeof username === 'string' ? username.trim().toLowerCase() : '';
  if (!/^[a-z0-9_]{3,30}$/.test(name) || !str(password, 8, 128)) return res.status(400).json({ error: 'اسم المستخدم 3-30 حرفًا إنجليزيًا/أرقام، وكلمة المرور 8 أحرف على الأقل.' });
  const hash = await bcrypt.hash(password, 12);
  try {
    const r = db.prepare('INSERT INTO users(username,hash,created) VALUES(?,?,?)').run(name, hash, now());
    res.json({ user: { id: r.lastInsertRowid, username: name, role: 'student' }, csrf: startSession(res, r.lastInsertRowid) });
  } catch { res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل.' }); }
}));

app.post('/api/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(sha(cookie(req, 'sid')));
  res.clearCookie('sid');
  res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json({ user: pub(req.user), csrf: req.user.csrf }));

// ---------- الطالب ----------
function canOpen(user, lesson) {
  if (user.role === 'admin') return true;
  if (!db.prepare('SELECT open FROM courses WHERE id = ?').get(lesson.course_id)?.open) return false;
  const prev = db.prepare('SELECT id FROM lessons WHERE course_id = ? AND pos < ? ORDER BY pos DESC LIMIT 1').get(lesson.course_id, lesson.pos);
  return !prev || !!db.prepare('SELECT 1 FROM submissions WHERE lesson_id = ? AND user_id = ?').get(prev.id, user.id);
}
app.get('/api/courses', auth, (req, res) => res.json(db.prepare('SELECT c.id, c.name, c.open, (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) AS total, (SELECT COUNT(*) FROM submissions s JOIN lessons l ON l.id = s.lesson_id WHERE l.course_id = c.id AND s.user_id = ?) AS done FROM courses c ORDER BY c.id').all(req.user.id)));
app.get('/api/lessons', auth, (req, res) => {
  const cid = Number(req.query.course);
  const c = db.prepare('SELECT open FROM courses WHERE id = ?').get(cid);
  if (!c) return res.status(404).json({ error: 'الكورس غير موجود.' });
  const rows = db.prepare('SELECT l.id, l.title, s.id AS sub, s.grade FROM lessons l LEFT JOIN submissions s ON s.lesson_id = l.id AND s.user_id = ? WHERE l.course_id = ? ORDER BY l.pos').all(req.user.id, cid);
  const shut = !c.open && req.user.role !== 'admin';
  let prevDone = true;
  res.json(rows.map(r => {
    const locked = shut || (req.user.role !== 'admin' && !prevDone);
    prevDone = !!r.sub;
    return { id: r.id, title: r.title, grade: r.grade, done: !!r.sub, locked };
  }));
});
app.get('/api/lessons/:id', auth, (req, res) => {
  const l = db.prepare('SELECT * FROM lessons WHERE id = ?').get(Number(req.params.id));
  if (!l) return res.status(404).json({ error: 'الدرس غير موجود.' });
  if (!canOpen(req.user, l)) return res.status(403).json({ error: 'سلّم واجب الدرس السابق أولًا.' });
  const submission = db.prepare('SELECT answer, grade, feedback FROM submissions WHERE lesson_id = ? AND user_id = ?').get(l.id, req.user.id) || null;
  res.json({ lesson: { id: l.id, title: l.title, content: l.content, homework: l.homework }, submission });
});
app.post('/api/lessons/:id/submit', auth, (req, res) => {
  const l = db.prepare('SELECT * FROM lessons WHERE id = ?').get(Number(req.params.id));
  if (!l) return res.status(404).json({ error: 'الدرس غير موجود.' });
  if (!canOpen(req.user, l)) return res.status(403).json({ error: 'سلّم واجب الدرس السابق أولًا.' });
  const { answer } = req.body || {};
  if (!str(answer, 1, 10000)) return res.status(400).json({ error: 'اكتب إجابة (حتى 10000 حرف).' });
  const r = db.prepare('INSERT INTO submissions(lesson_id,user_id,answer,created) VALUES(?,?,?,?) ON CONFLICT(lesson_id,user_id) DO UPDATE SET answer = excluded.answer, created = excluded.created WHERE grade IS NULL')
    .run(l.id, req.user.id, answer, now());
  if (!r.changes) return res.status(409).json({ error: 'تم تصحيح هذا الواجب ولا يمكن تعديله.' });
  res.json({ ok: true });
});

// ---------- الأدمن ----------
const adm = [auth, admin];
app.get('/api/admin/stats', adm, (req, res) => res.json({
  students: db.prepare("SELECT COUNT(*) c FROM users WHERE role='student'").get().c,
  lessons: db.prepare('SELECT COUNT(*) c FROM lessons').get().c,
  submissions: db.prepare('SELECT COUNT(*) c FROM submissions').get().c,
  pending: db.prepare('SELECT COUNT(*) c FROM submissions WHERE grade IS NULL').get().c,
}));
app.get('/api/admin/lessons', adm, (req, res) => res.json(db.prepare('SELECT l.id, l.pos, l.title, c.name AS course FROM lessons l JOIN courses c ON c.id = l.course_id ORDER BY l.course_id, l.pos').all()));
app.patch('/api/admin/courses/:id', adm, (req, res) => {
  db.prepare('UPDATE courses SET open = ? WHERE id = ?').run(req.body?.open ? 1 : 0, Number(req.params.id));
  res.json({ ok: true });
});
app.post('/api/admin/lessons', adm, (req, res) => {
  const { course_id, title, content, homework } = req.body || {};
  if (!db.prepare('SELECT 1 FROM courses WHERE id = ?').get(Number(course_id))) return res.status(400).json({ error: 'اختر الكورس.' });
  if (!str(title, 3, 150) || !str(content, 1, 20000) || !str(homework, 1, 5000)) return res.status(400).json({ error: 'أكمل العنوان والشرح والواجب.' });
  const pos = (db.prepare('SELECT MAX(pos) m FROM lessons WHERE course_id = ?').get(Number(course_id)).m || 0) + 1;
  db.prepare('INSERT INTO lessons(course_id,pos,title,content,homework) VALUES(?,?,?,?,?)').run(Number(course_id), pos, title.trim(), content, homework);
  res.json({ ok: true });
});
app.delete('/api/admin/lessons/:id', adm, (req, res) => {
  db.prepare('DELETE FROM lessons WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});
app.get('/api/admin/students', adm, (req, res) => res.json(db.prepare("SELECT u.id, u.username, u.active, u.created, (SELECT COUNT(*) FROM submissions s WHERE s.user_id = u.id) AS done FROM users u WHERE u.role = 'student' ORDER BY u.id DESC").all()));
app.patch('/api/admin/students/:id', adm, (req, res) => {
  const id = Number(req.params.id), active = req.body?.active ? 1 : 0;
  db.prepare("UPDATE users SET active = ? WHERE id = ? AND role = 'student'").run(active, id);
  if (!active) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  res.json({ ok: true });
});
app.delete('/api/admin/students/:id', adm, (req, res) => {
  db.prepare("DELETE FROM users WHERE id = ? AND role = 'student'").run(Number(req.params.id));
  res.json({ ok: true });
});
app.get('/api/admin/submissions', adm, (req, res) => res.json(db.prepare('SELECT s.id, u.username, c.name AS course, l.title, s.answer, s.grade, s.feedback FROM submissions s JOIN users u ON u.id = s.user_id JOIN lessons l ON l.id = s.lesson_id JOIN courses c ON c.id = l.course_id ORDER BY s.grade IS NOT NULL, s.created DESC LIMIT 200').all()));
app.post('/api/admin/submissions/:id/grade', adm, (req, res) => {
  const { grade, feedback } = req.body || {};
  if (!Number.isInteger(grade) || grade < 0 || grade > 100 || (feedback != null && !str(String(feedback), 0, 2000))) return res.status(400).json({ error: 'الدرجة من 0 إلى 100.' });
  db.prepare('UPDATE submissions SET grade = ?, feedback = ? WHERE id = ?').run(grade, feedback || '', Number(req.params.id));
  res.json({ ok: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'غير موجود.' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => {
  const code = err.status === 400 || err.type === 'entity.parse.failed' ? 400 : err.status === 413 ? 413 : 500;
  if (code === 500) console.error(err);
  res.status(code).json({ error: code === 500 ? 'حدث خطأ في الخادم.' : 'طلب غير صالح.' });
});

setInterval(() => db.prepare('DELETE FROM sessions WHERE expires < ?').run(now()), 3600e3).unref();
app.listen(process.env.PORT || 3000, () => console.log('منصة عبدالله السيد تعمل على المنفذ ' + (process.env.PORT || 3000)));
