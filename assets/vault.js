/*
 * The owner's side of end-to-end encryption (src/e2e.php), on every page of a signed-in owner (layout.php
 * puts their keyring on the page). It promotes the unlock key from signing in (password.js), makes the
 * owner's key the first time, locks keys again when the password changes, sends the login value instead
 * of the password where a page asks to confirm it, makes the backup key, opens keys that are still
 * locked with an earlier password, and on the results page opens the sealed answers and shows them as
 * results.php and responses.php would, with the download made here.
 */
(() => {
  const E = globalThis.MijnE2E;
  const ringBlock = document.getElementById('keyring');
  if (!ringBlock || !E) return;
  const ring = JSON.parse(ringBlock.textContent);
  const pageBlock = document.getElementById('vault');
  const boot = pageBlock ? JSON.parse(pageBlock.textContent) : {};
  const texts = Object.assign({}, ring.t, boot.t);
  const T = (key, vars = {}) => (texts[key] || key).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m));
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined) node.append(c);
    return node;
  }

  /** A translated text with {placeholders} filled by DOM nodes or text: never HTML from a string. */
  function fill(template, vars) {
    const frag = document.createDocumentFragment();
    for (const part of template.split(/(\{\w+\})/)) {
      const m = part.match(/^\{(\w+)\}$/);
      if (m && m[1] in vars) frag.append(vars[m[1]]);
      else if (part) frag.append(part);
    }
    return frag;
  }

  /** Text with its line breaks kept. */
  function lines(text) {
    const frag = document.createDocumentFragment();
    String(text).split('\n').forEach((line, i) => { if (i) frag.append(el('br')); frag.append(line); });
    return frag;
  }

  function showError(target, message) {
    if (!target) return;
    target.textContent = message || '';
    target.hidden = !message;
  }

  function busy(button, text) {
    if (!button) return;
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.disabled = !!text;
    button.textContent = text || button.dataset.label;
  }

  function hidden(form, name, value) {
    let input = form.querySelector(`input[type=hidden][name="${name}"]`);
    if (!input) {
      input = el('input', { type: 'hidden', name });
      form.append(input);
    }
    input.value = value;
  }

  const unsupported = !E.supported;
  const BROWSER = 'Deze browser kan geen sleutels maken of openen. Gebruik een recente versie van Firefox, Chrome, Edge of Safari.';

  /* --- The keys ------------------------------------------------------------ */

  /** Keys the current password opens, and keys still locked with an earlier one. */
  const current = () => ring.keys.filter((k) => k.salt === ring.salt && k.wrap);
  const locked = () => ring.keys.filter((k) => k.salt !== ring.salt);

  async function post(url, fields) {
    const body = new URLSearchParams(Object.assign({ csrf: ring.csrf }, fields));
    const res = await fetch(url, { method: 'POST', body, credentials: 'same-origin', headers: { Accept: 'application/json' } });
    let data = {};
    try { data = await res.json(); } catch { /* not JSON */ }
    if (!res.ok) { const err = new Error(data.error || String(res.status)); err.code = data.error; throw err; }
    return data;
  }

  /** Whether this unlock key opens the keys of the current password (true when there are none to try). */
  async function opens(unlock) {
    const k = current()[0];
    if (!k) return true;
    try { await E.unwrapKey(unlock, k.public, k.wrap); return true; } catch { return false; }
  }

  /**
   * The unlock key for the current password on this device. One from a sign-in is confirmed here: this
   * page is signed in, so the last password typed at sign-in was the right one.
   */
  let unlockCache = null;
  async function unlockKey() {
    if (unlockCache) return unlockCache;
    const pending = await E.recall('p', ring.salt);
    if (pending) {
      await E.store('w', ring.salt, pending);
      await E.remove('p', ring.salt);
    }
    const key = pending || (await E.recall('w', ring.salt));
    if (key && !(await opens(key))) { await E.remove('w', ring.salt); return null; }
    unlockCache = key;
    return key;
  }

  function keyChanged() {
    $$('[data-vault-nokey]').forEach((n) => { n.hidden = current().length > 0; });
    $$('[data-vault-haskey]').forEach((n) => { n.hidden = current().length === 0; });
    $$('[data-vault-locked]').forEach((n) => { n.hidden = locked().length === 0; });
  }

  /** A new key pair, locked with the unlock key and sealed for the backup key when there is one. */
  async function createKey(unlock, extra = {}) {
    const { publicKey, pkcs8 } = await E.createKeyPair();
    const fields = Object.assign({ public: publicKey, wrap: await E.wrapKey(unlock, publicKey, pkcs8) }, extra);
    if (ring.backupPublic) fields.backup = await E.backupSeal(ring.backupPublic, publicKey, pkcs8);
    const r = await post('/account/sleutels', fields);
    ring.v = 1;
    ring.keys.push({ id: r.id, public: publicKey, salt: ring.salt, wrap: fields.wrap, backup: fields.backup || null });
    keyChanged();
  }

  /** Keys opened some other way ({id: bytes}), locked again with the current password. */
  async function relock(opened, unlock) {
    const wraps = {};
    for (const k of ring.keys) if (opened[k.id]) wraps[k.id] = await E.wrapKey(unlock, k.public, opened[k.id]);
    if (!Object.keys(wraps).length) return 0;
    await post('/account/sleutels/terugzetten', { wraps: JSON.stringify(wraps) });
    for (const k of ring.keys) if (wraps[k.id]) { k.wrap = wraps[k.id]; k.salt = ring.salt; }
    keyChanged();
    return Object.keys(wraps).length;
  }

  /** Locked keys this device can still open: it kept the unlock key of that earlier password. */
  async function relockFromDevice(unlock) {
    const opened = {};
    for (const k of locked()) {
      const old = await E.recall('w', k.salt);
      if (!old) continue;
      try { opened[k.id] = await E.unwrapKey(old, k.public, k.wrap); } catch { /* not this one */ }
    }
    return relock(opened, unlock);
  }

  /** Locked keys opened with an earlier password or the backup code. Throws Error('wrong') when neither fits. */
  async function relockWith(secret, unlock) {
    const opened = {};
    if (E.codeBytes(secret) && ring.backupWrapped) {
      try {
        const backup = await E.openBackup(secret, ring.backupPublic, ring.backupWrapped);
        for (const k of locked()) {
          if (k.backup) try { opened[k.id] = await E.backupOpen(backup, k.public, k.backup); } catch { /* sealed for an older backup key */ }
        }
      } catch { /* not the backup code: perhaps a password */ }
    }
    if (!Object.keys(opened).length) {
      for (const salt of new Set(locked().map((k) => k.salt))) {
        const { unlock: old } = await E.derive(secret, salt);
        for (const k of locked().filter((x) => x.salt === salt)) {
          try { opened[k.id] = await E.unwrapKey(old, k.public, k.wrap); } catch { /* another password */ }
        }
        if (Object.keys(opened).length) await E.store('w', salt, old);
      }
    }
    if (!Object.keys(opened).length) throw new Error('wrong');
    return relock(opened, unlock);
  }

  /** The private keys the current password opens, ready to use, by id. */
  async function privateKeys(unlock) {
    const out = new Map();
    for (const k of current()) {
      try { out.set(k.id, await E.usable(await E.unwrapKey(unlock, k.public, k.wrap))); } catch { /* damaged */ }
    }
    return out;
  }

  /* --- Asking for the password ----------------------------------------------
   * Only when this device has no unlock key: signed in without JavaScript, or before this existed. */

  function askPassword() {
    const panel = $('[data-vault-unlock]');
    if (!panel) return new Promise(() => {});
    const form = $('form', panel);
    const error = $('[data-vault-unlock-error]', panel);
    const input = $('input[type=password]', form);
    const button = $('button', form);
    panel.hidden = false;
    return new Promise((resolve) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        showError(error, '');
        busy(button, T('Ontgrendelen…'));
        try {
          const d = await E.derive(input.value, ring.salt);
          if (current().length) {
            if (!(await opens(d.unlock))) throw new Error('password');
          } else {
            // No key yet to check the password against: the server checks it, and the key is made with it.
            await createKey(d.unlock, ring.v === 1 ? { current_password_auth: d.auth } : { current_password: input.value });
          }
          await E.store('w', ring.salt, d.unlock);
          unlockCache = d.unlock;
          input.value = '';
          panel.hidden = true;
          resolve(d.unlock);
        } catch (err) {
          showError(error, err.message === 'password' ? T('Je wachtwoord klopt niet.') : T(BROWSER));
          input.setAttribute('aria-invalid', 'true');
          input.focus();
        } finally {
          busy(button, null);
        }
      });
    });
  }

  async function getUnlock() {
    return (await unlockKey()) || askPassword();
  }

  /** The form for opening keys locked with an earlier password, wherever the page has one. */
  function restoreForm(onDone) {
    const panel = $('[data-vault-restore]');
    if (!panel || !locked().length) return;
    panel.hidden = false;
    const form = $('form', panel);
    const input = $('input', form);
    const error = $('[data-vault-restore-error]', panel);
    const button = $('button', form);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      showError(error, '');
      busy(button, T('Ontgrendelen…'));
      try {
        const unlock = await getUnlock();
        await relockWith(input.value, unlock);
        input.value = '';
        panel.hidden = !locked().length;
        const done = $('[data-vault-restore-done]', panel.parentNode);
        if (done) { done.textContent = T('Je oudere antwoorden zijn weer te openen.'); done.hidden = false; }
        if (onDone) onDone();
      } catch (err) {
        showError(error, err.message === 'wrong' ? T('Dit wachtwoord of deze back-upsleutel opent geen van je oudere sleutels.') : T(BROWSER));
      } finally {
        busy(button, null);
      }
    });
  }

  /* --- Forms that ask for the password ---------------------------------------
   * The login value goes to the server instead; the password field itself is never sent. The fields come
   * disabled from the server and are enabled only once this file handles their form (see below). */

  const FAILED = 'Niet verstuurd: je wachtwoord kon in deze browser niet veilig worden voorbereid. Probeer het opnieuw.';

  /** Problems with a new password. Only checked here: the server never gets the password to check. */
  function passwordProblem(password, notLike) {
    if ([...password].length < 10) return T('Kies een wachtwoord van minstens 10 tekens.');
    if (new TextEncoder().encode(password).length > 200) return T('Kies een wachtwoord van hoogstens 200 tekens.');
    if (notLike.some((o) => o && o.toLowerCase() === password.toLowerCase())) return T('Kies een wachtwoord dat niet gelijk is aan je naam of e-mailadres.');
    if (/^(.)\1+$/u.test(password) || ['1234567890', 'wachtwoord123', 'password123', 'qwertyuiop'].includes(password.toLowerCase())) {
      return T('Dit wachtwoord is te makkelijk te raden. Kies een ander.');
    }
    return null;
  }

  function formError(form, message) {
    let p = $('[data-vault-form-error]', form);
    if (!p) {
      p = el('p', { class: 'error', 'data-vault-form-error': true, role: 'alert' });
      $('button[type=submit]', form).before(p);
    }
    showError(p, message);
  }

  /**
   * Fill in the login value for current_password, and check it here when a key can tell. Returns the
   * derived values, or null when the password is wrong (the form then shows why).
   */
  async function confirmPassword(form) {
    const input = form.elements.current_password;
    if (!input || ring.v !== 1) return { auth: null, unlock: null };
    const d = await E.derive(input.value, ring.salt);
    if (current().length && !(await opens(d.unlock))) {
      formError(form, T('Je wachtwoord klopt niet.'));
      input.focus();
      return null;
    }
    hidden(form, 'current_password_auth', d.auth);
    if (!(await E.recall('w', ring.salt))) await E.store('w', ring.salt, d.unlock);
    return d;
  }

  /** Submit, with the password fields whose login value is filled in no longer sent themselves. */
  function send(form) {
    for (const name of ['current_password', 'password']) {
      const input = form.elements[name];
      if (input && form.querySelector(`input[type=hidden][name="${name}_auth"]`)) input.removeAttribute('name');
    }
    form.submit();
  }

  /** A form that only confirms the password: email, two-step verification, deleting the account. */
  function confirmForm(form) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = $('button[type=submit]', form);
      busy(button, T('Even geduld…'));
      try {
        if (!(await confirmPassword(form))) { busy(button, null); return; }
      } catch {
        busy(button, null);
        formError(form, T(FAILED));
        return;
      }
      send(form);
    });
  }

  /** A new password: the keys it opens now are locked again with the new one, here. */
  function passwordForm(form) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = $('button[type=submit]', form);
      const input = form.elements.password;
      const why = passwordProblem(input.value, boot.notLike || []);
      formError(form, why);
      if (why) { input.focus(); return; }
      busy(button, T('Even geduld…'));
      try {
        const old = await confirmPassword(form);
        if (!old) { busy(button, null); return; }
        const salt = E.newSalt();
        const next = await E.derive(input.value, salt);
        if (old.unlock) {
          const rewrap = {};
          for (const k of current()) rewrap[k.id] = await E.wrapKey(next.unlock, k.public, await E.unwrapKey(old.unlock, k.public, k.wrap));
          hidden(form, 'rewrap', JSON.stringify(rewrap));
        }
        hidden(form, 'password_auth', next.auth);
        hidden(form, 'password_salt', salt);
        await E.store('w', salt, next.unlock);
      } catch {
        for (const name of ['current_password_auth', 'password_auth', 'password_salt', 'rewrap']) {
          const h = form.querySelector(`input[type=hidden][name="${name}"]`);
          if (h) h.remove();
        }
        busy(button, null);
        formError(form, T(FAILED));
        return;
      }
      send(form);
    });
  }

  /* --- The backup key ------------------------------------------------------- */

  function backupForm(form) {
    const button = $('button[type=submit]', form);
    const box = $('[data-vault-recovery]', form);
    let made = null;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      formError(form, '');
      if (made) {
        if (!$('[data-vault-recovery-ok]', box).checked) { formError(form, T('Bewaar eerst je back-upsleutel en vink aan dat je dat hebt gedaan.')); return; }
        busy(button, T('Opslaan…'));
        send(form);
        return;
      }
      busy(button, T('Even geduld…'));
      try {
        const d = await confirmPassword(form);
        if (!d) { busy(button, null); return; }
        const unlock = d.unlock || (await getUnlock());
        const backup = await E.createBackup();
        const seals = {};
        for (const k of current()) seals[k.id] = await E.backupSeal(backup.publicKey, k.public, await E.unwrapKey(unlock, k.public, k.wrap));
        hidden(form, 'backup_public', backup.publicKey);
        hidden(form, 'backup_wrapped', backup.wrapped);
        hidden(form, 'backups', JSON.stringify(seals));
        made = backup;
        busy(button, null);
        button.textContent = button.dataset.done;
        form.elements.current_password.readOnly = true;
        showCode(box, backup.code);
      } catch {
        busy(button, null);
        formError(form, T(BROWSER));
      }
    });
  }

  function showCode(box, code) {
    $('[data-vault-recovery-code]', box).textContent = code;
    $('[data-vault-recovery-ok]', box).checked = false;
    box.hidden = false;
    $('[data-vault-recovery-save]', box).onclick = () => {
      const text = [T('Back-upsleutel voor Mijn Enquête'), '', code, '', T('Account: {name}', { name: ring.name || '' }),
        T('Gemaakt op {date}', { date: ring.today || '' }), '',
        T('Met deze back-upsleutel open je je versleutelde antwoorden als je je wachtwoord kwijt bent. Bewaar hem op papier of in een wachtwoordbeheerder, niet in je e-mail.'), '']
        .join('\r\n');
      const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
      const a = el('a', { href: url, download: T('back-upsleutel-mijnenquete') + '.txt' });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    const copy = $('[data-vault-recovery-copy]', box);
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(code); copy.textContent = T('Gekopieerd'); } catch { /* the code is on screen */ }
      setTimeout(() => { copy.textContent = T('Kopiëren'); }, 2000);
    };
    box.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  /* --- Every page ----------------------------------------------------------- */

  async function start() {
    const unlock = await unlockKey();
    if (unlock && ring.v === 1) {
      if (locked().length) { try { await relockFromDevice(unlock); } catch { /* asked for on the account page */ } }
      if (!current().length) { try { await createKey(unlock); } catch { /* tried again on the next page */ } }
    }
    keyChanged();
    if (!current().length && !unlock && $('[data-vault-unlock][data-vault-ask]')) askPassword();
  }

  if (!unsupported) {
    for (const form of $$('form')) {
      if (form.matches('[data-vault-backup]')) backupForm(form);
      else if (form.matches('[data-vault-password]')) passwordForm(form);
      else if (form.elements.current_password) confirmForm(form);
      else continue;
      for (const input of $$('input[data-needs-crypto]', form)) {
        input.disabled = false;
        const note = $('[data-crypto-unavailable]', input.closest('.field'));
        if (note) note.hidden = true;
      }
    }
  } else {
    $$('[data-vault-browser]').forEach((n) => { n.textContent = T(BROWSER); n.hidden = false; });
  }
  const started = unsupported ? Promise.resolve() : start();
  if (!$('[data-vault-results]')) {
    started.then(() => restoreForm());
    return;
  }

  /* --- The results page --------------------------------------------------- */

  const status = $('[data-vault-status]');
  if (unsupported) {
    status.textContent = T('Deze browser kan geen versleutelde antwoorden openen. Gebruik een recente versie van Firefox, Chrome, Edge of Safari.');
    return;
  }

  const lang = { nl: 'nl-NL', en: 'en-GB', fr: 'fr-FR' }[boot.lang] || 'nl-NL';
  const decimal = new Intl.NumberFormat(lang, { minimumFractionDigits: 1, maximumFractionDigits: 1 });
  const day = new Intl.DateTimeFormat(lang, { day: 'numeric', month: 'short', year: 'numeric' });
  const showDate = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v) ? day.format(new Date(v + 'T12:00:00')) : v);
  const plural = (n, one, many) => T(n === 1 ? one : many, { n });

  let data = null;
  let people = [];

  /** Only what fits the question: a respondent's browser sealed it, so it is checked here. */
  function clean(questions, a) {
    const out = {};
    if (!a || typeof a !== 'object') return out;
    for (const q of questions) {
      const v = a[String(q.id)];
      if (q.type === 'multi') {
        if (Array.isArray(v)) { const list = v.filter((x) => typeof x === 'string'); if (list.length) out[q.id] = list; }
      } else if (typeof v === 'string' && v !== '') {
        out[q.id] = v;
      }
    }
    return out;
  }

  /* Failures in a row on this survey, kept across refreshes: from the third, the owner is asked to mail us. */
  const BUG_MAIL = 'foundabug@mijnenquete.nl';
  const failKey = 'mijnenquete:results-failures:' + boot.survey;
  const failures = (add) => {
    try {
      const n = add ? (Number(sessionStorage.getItem(failKey)) || 0) + 1 : 0;
      if (n) sessionStorage.setItem(failKey, String(n)); else sessionStorage.removeItem(failKey);
      return n;
    } catch { return add ? 1 : 0; }
  };

  /** A problem on the status line, with its code; when it keeps happening, where to report it. */
  function problem(message, code) {
    status.replaceChildren(message);
    if (failures(true) < 3) return;
    const subject = `Mijn Enquête: ${code} (${location.pathname})`;
    const link = el('a', { href: `mailto:${BUG_MAIL}?subject=${encodeURIComponent(subject)}` }, BUG_MAIL);
    status.append(' ', fill(T('Blijft dit misgaan? Mail {email} met foutcode {code}, dan zoeken we het uit.'), { email: link, code }));
  }

  async function load() {
    status.textContent = T('Antwoorden openen…');
    await started;
    const unlock = await getUnlock();
    status.textContent = T('Antwoorden openen…');
    const keys = await privateKeys(unlock);
    let res;
    try {
      res = await fetch(boot.data, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
    } catch {
      problem(T('Er is geen verbinding met de server. Controleer je internetverbinding en vernieuw de pagina.'), 'NET');
      return;
    }
    let body = null;
    try { body = await res.json(); } catch { /* not JSON: an error page in between */ }
    if (!res.ok || !body || !Array.isArray(body.responses)) {
      const code = 'HTTP ' + res.status;
      problem(res.status === 401 ? T('Je bent uitgelogd. Log opnieuw in om de antwoorden te bekijken.')
        : res.status === 404 ? T('Deze enquête is niet gevonden. Misschien is hij verwijderd of hoort hij bij een ander account.')
        : res.status >= 500 ? T('De server gaf een fout (foutcode {code}). Vernieuw de pagina over een paar minuten.', { code })
        : T('De antwoorden konden niet worden geladen (foutcode {code}). Vernieuw de pagina en probeer het opnieuw.', { code }), code);
      return;
    }
    data = body;
    let failed = 0;
    people = [];
    for (const r of data.responses) {
      let answers = r.answers;
      if (r.sealed) {
        answers = null;
        // The key it was sealed for first, then the others (a key can change while someone fills in the survey).
        const order = [keys.get(r.key), ...[...keys].filter(([id]) => id !== r.key).map(([, k]) => k)].filter(Boolean);
        for (const key of order) {
          try { answers = (await E.open(key, data.survey, r.sealed)).a; break; } catch { /* the next key */ }
        }
        if (answers === null) { failed++; continue; }
      }
      people.push({ id: r.id, at: r.at, date: r.date, time: r.time, stamp: r.stamp, answers: clean(data.questions, answers) });
    }
    if (!failed) {
      status.textContent = '';
      failures(false);
    } else if (locked().length) {
      // Not a fault: the form for the previous password is on this page.
      failures(false);
      status.textContent = failed === 1
        ? T('Eén antwoord zit nog op slot met je vorige wachtwoord.')
        : T('{n} antwoorden zitten nog op slot met je vorige wachtwoord.', { n: failed });
    } else {
      problem(failed === 1
        ? T('Eén antwoord kon niet worden geopend: het is met een andere sleutel versleuteld of beschadigd.')
        : T('{n} antwoorden konden niet worden geopend: ze zijn met een andere sleutel versleuteld of beschadigd.', { n: failed }),
      `KEY ${failed}/${data.responses.length}`);
    }
    $('[data-vault-tabs]').hidden = !people.length;
    $('[data-vault-csv]').hidden = !people.length;
    route();
  }

  /* The same summary as survey_results() in src/surveys.php. */
  function summarise(q) {
    const r = { answered: 0, kind: 'text', bars: [], average: null, texts: [] };
    const values = people.map((p) => p.answers[q.id]).filter((v) => v !== undefined);
    r.answered = values.length;
    if (['short', 'long', 'email', 'date'].includes(q.type)) {
      r.texts = values.slice(0, 50);
      return r;
    }
    const counts = new Map();
    for (const v of values) for (const label of q.type === 'multi' ? v : [v]) counts.set(label, (counts.get(label) || 0) + 1);
    let labels;
    if (q.type === 'stars' || q.type === 'scale') {
      const [min, max] = q.type === 'stars' ? [1, 5] : [q.min, q.max];
      labels = [];
      for (let i = min; i <= max; i++) labels.push(String(i));
      let sum = 0;
      for (const [label, n] of counts) sum += Number(label) * n;
      r.average = r.answered ? sum / r.answered : null;
      r.kind = 'number';
    } else {
      labels = q.type === 'yesno' ? ['Ja', 'Nee'] : [...q.choices];
      for (const label of counts.keys()) if (!labels.includes(label)) labels.push(label);
      r.kind = 'choice';
    }
    r.bars = labels.map((label) => ({ label, n: counts.get(label) || 0 }));
    return r;
  }

  function bar(n, of) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'bar');
    svg.setAttribute('viewBox', '0 0 100 8');
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('aria-hidden', 'true');
    for (const [cls, w] of [['bar-track', 100], ['bar-fill', of > 0 ? Math.round((n / of) * 1000) / 10 : 0]]) {
      const rect = document.createElementNS(ns, 'rect');
      rect.setAttribute('class', cls);
      rect.setAttribute('width', String(w));
      rect.setAttribute('height', '8');
      svg.append(rect);
    }
    return svg;
  }

  function renderSummary() {
    const box = $('[data-vault-summary]');
    box.replaceChildren();
    if (!people.length) return;
    const total = people.length;
    const last = people[0];
    box.append(el('p', { class: 'total' },
      fill(T(total === 1 ? '{n} antwoord' : '{n} antwoorden'), { n: el('b', { text: String(total) }) }),
      el('span', { class: 'muted', text: T(', het laatste op {date} om {time}', { date: last.date, time: last.time }) })));
    const list = el('ol', { class: 'result-list' });
    for (const q of data.questions) {
      const r = summarise(q);
      const item = el('li', { class: 'result' }, el('h2', { text: q.title }),
        el('p', { class: 'muted', text: T('{type}, {n} van {total} beantwoord', { type: boot.types[q.type] || q.type, n: r.answered, total }) }));
      if (r.kind === 'text') {
        if (!r.texts.length) item.append(el('p', { class: 'muted', text: T('Niemand heeft deze vraag ingevuld.') }));
        else {
          item.append(el('ul', { class: 'texts' }, r.texts.map((t) => el('li', {}, lines(q.type === 'date' ? showDate(t) : t)))));
          if (r.answered > r.texts.length) item.append(el('p', { class: 'muted', text: T('Dit zijn de laatste {n}. De download bevat ze allemaal.', { n: r.texts.length }) }));
        }
      } else {
        if (r.average !== null) {
          item.append(el('p', { class: 'average' }, el('b', { text: decimal.format(r.average) }), ' ',
            q.type === 'stars' ? T('gemiddeld van de 5 sterren') : T('gemiddeld')));
        }
        const tallies = el('div', { class: 'tallies' });
        for (const b of r.bars) {
          const label = q.type === 'stars' ? plural(Number(b.label), '{n} ster', '{n} sterren') : (q.type === 'yesno' ? T(b.label) : b.label);
          const pct = r.answered ? Math.round((b.n / r.answered) * 100) : 0;
          tallies.append(el('div', { class: 'tally' }, el('span', { class: 'tally-label', text: label }), bar(b.n, Math.max(1, r.answered)),
            el('span', { class: 'tally-n' }, String(b.n), el('span', { class: 'muted', text: ` (${pct}%)` }))));
        }
        item.append(tallies);
        if (q.type === 'multi') item.append(el('p', { class: 'muted', text: T('Bij deze vraag kon je meer antwoorden kiezen, dus de percentages tellen op tot meer dan 100.') }));
      }
      list.append(item);
    }
    box.append(list);
  }

  /* One person at a time, newest first, like responses.php. */
  function shown(q, v) {
    if (v === undefined || v === '') return null;
    switch (q.type) {
      case 'multi': return v.join(', ');
      case 'date': return showDate(v);
      case 'yesno': return T(v);
      case 'stars': return T('{n} van de 5 sterren', { n: v });
      case 'scale': return T('{n} op een schaal van {min} tot {max}', { n: v, min: q.min, max: q.max });
      default: return v;
    }
  }

  function renderPerson(nr) {
    const box = $('[data-vault-person]');
    box.replaceChildren();
    const total = people.length;
    nr = Math.max(1, Math.min(total, nr));
    const p = people[nr - 1];
    const link = (n, text, off) => el('a', { class: 'btn btn-ghost btn-s' + (off ? ' is-off' : ''), href: '#persoon-' + n,
      'aria-disabled': off ? 'true' : null, tabindex: off ? '-1' : null, text });
    box.append(el('div', { class: 'pager' },
      link(Math.max(1, nr - 1), T('Nieuwer'), nr <= 1),
      el('p', {}, el('b', { text: T('Antwoord {nr}', { nr }) }), ' ', T('van {total}', { total }),
        el('span', { class: 'muted', text: T(', ingevuld op {date} om {time}', { date: p.date, time: p.time }) })),
      link(Math.min(total, nr + 1), T('Ouder'), nr >= total)));
    const dl = el('dl', { class: 'one-response' });
    data.questions.forEach((q, i) => {
      const text = shown(q, p.answers[q.id]);
      dl.append(el('div', {}, el('dt', {}, el('span', { class: 'q-n', 'aria-hidden': 'true', text: String(i + 1) }), ' ', q.title),
        el('dd', { class: text === null ? 'muted' : null }, text === null ? T('Niet ingevuld') : lines(text))));
    });
    box.append(dl);
    if (boot.canDelete) {
      const form = el('form', { method: 'post', action: boot.deleteUrl.replace('{id}', String(p.id)) },
        el('input', { type: 'hidden', name: 'csrf', value: boot.csrf }),
        el('input', { type: 'hidden', name: 'nr', value: String(nr) }),
        el('p', { text: T('Bijvoorbeeld een test of een dubbele inzending. Het verdwijnt ook uit de samenvatting en de download, en kan niet worden teruggezet.') }),
        el('button', { class: 'btn btn-danger', type: 'submit', text: T('Antwoord {nr} verwijderen', { nr }) }));
      box.append(el('details', { class: 'delete-one' }, el('summary', { text: T('Dit antwoord verwijderen') }), form));
    }
  }

  function route() {
    if (!data) return;
    const m = location.hash.match(/^#persoon-(\d+)$/);
    const person = !!m && people.length > 0;
    $('[data-vault-summary]').hidden = person;
    $('[data-vault-person]').hidden = !person;
    const [sumTab, personTab] = $$('[data-vault-tabs] a');
    if (person) { sumTab.removeAttribute('aria-current'); personTab.setAttribute('aria-current', 'page'); renderPerson(Number(m[1])); }
    else { personTab.removeAttribute('aria-current'); sumTab.setAttribute('aria-current', 'page'); renderSummary(); }
  }
  window.addEventListener('hashchange', route);

  /* The download, made here: the same columns and Excel-friendly format as page_survey_csv(). */
  const csvSafe = (v) => (/^[=+\-@\t\r]/.test(v) ? "'" + v : v);
  const csvCell = (v) => (/[;"\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v);
  $('[data-vault-csv]').addEventListener('click', () => {
    const rows = [[T('Ingevuld op'), ...data.questions.map((q) => csvSafe(q.title))]];
    for (const p of [...people].reverse()) {
      rows.push([p.stamp, ...data.questions.map((q) => {
        const v = p.answers[q.id];
        return csvSafe(v === undefined ? '' : (Array.isArray(v) ? v.join(', ') : v));
      })]);
    }
    const text = '﻿' + rows.map((r) => r.map(csvCell).join(';')).join('\n') + '\n';
    const name = (boot.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'enquete') + '-' + T('antwoorden') + '.csv';
    const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  started.then(() => restoreForm(load));
  load().catch((error) => {
    console.error(error);
    problem(T('Er ging iets mis bij het openen van de antwoorden. Vernieuw de pagina en probeer het opnieuw.'), 'JS ' + (error && error.name || 'Error'));
  });
})();
