'use strict';
const root = document.getElementById('app');
let me = null, csrf = '';

// كل النصوص تُدرج كنصوص عادية (لا innerHTML إطلاقًا) لمنع هجمات XSS
const h = (tag, props = {}, ...kids) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  el.append(...kids.flat().filter(x => x != null && x !== false));
  return el;
};

async function api(method, url, body) {
  const r = await fetch(url, {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: body ? JSON.stringify(body) : undefined,
  });
  const d = await r.json().catch(() => ({}));
  if (r.status === 401 && me) { me = null; render(); }
  if (!r.ok) throw new Error(d.error || 'حدث خطأ');
  return d;
}

let tt;
function flash(text, bad) {
  document.getElementById('toast')?.remove();
  document.body.append(h('div', { id: 'toast', class: bad ? 'bad' : '', role: 'status' }, text));
  clearTimeout(tt); tt = setTimeout(() => document.getElementById('toast')?.remove(), 3500);
}
const run = fn => (...a) => Promise.resolve(fn(...a)).catch(e => flash(e.message, true));

function render() {
  const head = h('header', {}, h('div', { class: 'brand' }, 'منصة ', h('span', {}, 'عبدالله السيد')),
    me && h('button', { onclick: run(async () => { await api('POST', '/api/logout'); me = null; csrf = ''; render(); }) }, 'خروج'));
  root.replaceChildren(head, h('main', {}, !me ? loginView() : me.role === 'admin' ? adminView() : studentView()));
}

function loginView() {
  let mode = 'login';
  const box = h('div', { class: 'card auth' });
  const draw = () => {
    const u = h('input', { autocomplete: 'username', required: true, maxlength: 30, placeholder: 'اسم المستخدم', dir: 'ltr' });
    const p = h('input', { type: 'password', autocomplete: mode === 'login' ? 'current-password' : 'new-password', required: true, maxlength: 128, placeholder: 'كلمة المرور', dir: 'ltr' });
    const form = h('form', { onsubmit: run(async e => {
      e.preventDefault();
      const d = await api('POST', mode === 'login' ? '/api/login' : '/api/register', { username: u.value, password: p.value });
      me = d.user; csrf = d.csrf; render();
    }) }, h('h2', {}, mode === 'login' ? 'تسجيل الدخول' : 'حساب طالب جديد'), u, p,
      h('button', { class: 'btn' }, mode === 'login' ? 'دخول' : 'إنشاء الحساب'));
    box.replaceChildren(form, h('button', { type: 'button', class: 'link', onclick: () => { mode = mode === 'login' ? 'register' : 'login'; draw(); } },
      mode === 'login' ? 'طالب جديد؟ أنشئ حسابك' : 'لديك حساب؟ سجّل الدخول'));
  };
  draw();
  return box;
}

// ---------- الطالب ----------
function studentView() {
  const box = h('div');
  let cur = null;
  const courses = run(async () => {
    const cs = await api('GET', '/api/courses');
    box.replaceChildren(h('h2', {}, 'الكورسات'), h('div', { class: 'grid' }, cs.map(c => h('button', {
      class: 'card course' + (c.open ? '' : ' locked'), disabled: !c.open, onclick: () => list(c),
    }, h('b', {}, c.name), h('div', { class: 'badge' }, !c.open ? 'الكورس مقفول' : c.total ? c.done + ' من ' + c.total + ' واجب' : 'لا توجد دروس بعد')))));
  });
  const list = run(async c => {
    cur = c;
    const ls = await api('GET', '/api/lessons?course=' + c.id);
    box.replaceChildren(h('button', { class: 'btn ghost sm', onclick: courses }, 'كل الكورسات'), h('h2', {}, c.name),
      ls.length ? h('div', { class: 'path' }, ls.map((l, i) => h('button', {
        class: 'card step' + (l.done ? ' done' : '') + (l.locked ? ' locked' : ''), 'data-n': i + 1,
        disabled: l.locked, onclick: () => open(l.id),
      }, h('b', {}, l.title), h('span', { class: 'badge' }, l.locked ? 'سلّم واجب الدرس السابق' : l.done ? (l.grade == null ? 'تم التسليم - بانتظار التصحيح' : 'الدرجة ' + l.grade + '/100') : 'ابدأ الدرس'))))
        : h('p', {}, 'لا توجد دروس في هذا الكورس بعد.'));
  });
  const open = run(async id => {
    const { lesson, submission } = await api('GET', '/api/lessons/' + id);
    const graded = submission && submission.grade != null;
    const ta = h('textarea', { class: 'code', maxlength: 10000, disabled: graded, placeholder: 'اكتب حلّك أو الكود هنا' });
    ta.value = submission ? submission.answer : '';
    box.replaceChildren(
      h('button', { class: 'btn ghost sm', onclick: () => list(cur) }, 'رجوع للدروس'),
      h('div', { class: 'card' }, h('h2', {}, lesson.title), h('div', { class: 'prose' }, lesson.content)),
      h('div', { class: 'card hw' }, h('h3', {}, 'واجب الدرس'), h('div', { class: 'prose' }, lesson.homework), h('br'), ta,
        graded
          ? h('p', {}, h('b', {}, 'الدرجة: ' + submission.grade + '/100'), submission.feedback ? ' - ' + submission.feedback : '')
          : h('button', { class: 'btn', onclick: run(async () => { await api('POST', '/api/lessons/' + id + '/submit', { answer: ta.value }); flash('تم تسليم الواجب'); list(cur); }) }, 'سلّم الواجب')));
  });
  courses();
  return box;
}

// ---------- الأدمن ----------
function adminView() {
  const body = h('div'), nav = h('nav', { class: 'tabs' });
  const tabs = { 'نظرة عامة': overview, 'الدروس': lessons, 'الطلاب': students, 'التسليمات': subs };
  const go = name => {
    [...nav.children].forEach(b => b.classList.toggle('on', b.textContent === name));
    tabs[name]().catch(e => flash(e.message, true));
  };
  Object.keys(tabs).forEach(n => nav.append(h('button', { onclick: () => go(n) }, n)));

  async function overview() {
    const s = await api('GET', '/api/admin/stats');
    const c = (n, t) => h('div', { class: 'card' }, h('b', {}, String(n)), t);
    body.replaceChildren(h('div', { class: 'stats' }, c(s.students, 'طالب'), c(s.lessons, 'درس'), c(s.submissions, 'واجب مُسلَّم'), c(s.pending, 'بانتظار التصحيح')));
  }
  async function lessons() {
    const [ls, cs] = await Promise.all([api('GET', '/api/admin/lessons'), api('GET', '/api/courses')]);
    const sel = h('select', {}, cs.map(x => h('option', { value: x.id }, x.name)));
    const t = h('input', { maxlength: 150, placeholder: 'عنوان الدرس' });
    const c = h('textarea', { maxlength: 20000, placeholder: 'شرح الدرس' });
    const w = h('textarea', { maxlength: 5000, placeholder: 'واجب الدرس' });
    body.replaceChildren(
      h('div', { class: 'card' }, h('h3', {}, 'قفل / فتح الكورسات'), h('div', { class: 'tabs' }, cs.map(x => h('button', {
        class: x.open ? 'on' : '', onclick: run(async () => { await api('PATCH', '/api/admin/courses/' + x.id, { open: !x.open }); lessons(); }),
      }, x.name + (x.open ? ' - مفتوح' : ' - مقفول'))))),
      h('form', { class: 'card', onsubmit: run(async e => {
        e.preventDefault();
        await api('POST', '/api/admin/lessons', { course_id: Number(sel.value), title: t.value, content: c.value, homework: w.value });
        flash('تمت إضافة الدرس'); lessons();
      }) }, h('h3', {}, 'درس جديد'), sel, t, c, w, h('button', { class: 'btn' }, 'إضافة الدرس')),
      ls.map(l => h('div', { class: 'card row' }, h('b', {}, l.course + ' - ' + l.pos + '. ' + l.title),
        h('button', { class: 'btn bad sm', onclick: run(async () => { if (confirm('حذف الدرس وكل تسليماته؟')) { await api('DELETE', '/api/admin/lessons/' + l.id); lessons(); } }) }, 'حذف'))));
  }
  async function students() {
    const st = await api('GET', '/api/admin/students');
    body.replaceChildren(st.length ? st.map(s => h('div', { class: 'card row' },
      h('div', {}, h('b', {}, s.username), h('span', { class: 'badge' }, '  واجبات: ' + s.done + (s.active ? '' : '  (موقوف)'))),
      h('div', {},
        h('button', { class: 'btn ghost sm', onclick: run(async () => { await api('PATCH', '/api/admin/students/' + s.id, { active: !s.active }); students(); }) }, s.active ? 'إيقاف' : 'تفعيل'),
        h('button', { class: 'btn bad sm', onclick: run(async () => { if (confirm('حذف الطالب نهائيًا؟')) { await api('DELETE', '/api/admin/students/' + s.id); students(); } }) }, 'حذف')))) : h('p', {}, 'لا يوجد طلاب مسجّلون بعد.'));
  }
  async function subs() {
    const ss = await api('GET', '/api/admin/submissions');
    body.replaceChildren(ss.length ? ss.map(s => {
      const g = h('input', { type: 'number', min: 0, max: 100, placeholder: 'الدرجة' });
      const f = h('input', { maxlength: 2000, placeholder: 'ملاحظاتك للطالب' });
      if (s.grade != null) g.value = s.grade;
      f.value = s.feedback || '';
      return h('div', { class: 'card' }, h('b', {}, s.username + ' - ' + s.course + ' - ' + s.title), h('pre', {}, s.answer),
        h('div', { class: 'mini' }, g, f, h('button', { class: 'btn sm', onclick: run(async () => {
          await api('POST', '/api/admin/submissions/' + s.id + '/grade', { grade: parseInt(g.value, 10), feedback: f.value });
          flash('تم حفظ التقييم');
        }) }, 'حفظ')));
    }) : h('p', {}, 'لا توجد تسليمات بعد.'));
  }

  go('نظرة عامة');
  return h('div', {}, h('h2', {}, 'لوحة تحكم الأدمن'), nav, body);
}

// استعادة الجلسة عند فتح الصفحة
api('GET', '/api/me').then(d => { me = d.user; csrf = d.csrf; }).catch(() => {}).finally(render);
