/* Ordinary surveys work without scripts; encrypted surveys require browser encryption before filling in. */
(async () => {
  const summary = document.querySelector('[data-error-summary]');
  if (summary) {
    const first = document.querySelector('.sq-error');
    (first || summary).scrollIntoView({ block: 'center' });
    const control = first && first.querySelector('input, textarea, select');
    (control || summary).focus({ preventScroll: true });
  }

  const form = document.querySelector('.survey form[novalidate]');
  if (!form) return;
  const button = form.querySelector('button[type=submit]');
  const label = button.textContent;
  const busy = (on) => { button.disabled = on; button.textContent = on ? (button.dataset.sending || label) : label; };

  const sealBlock = document.getElementById('seal');
  const E = globalThis.MijnE2E;
  let seal = null;
  const T = (key, vars = {}) => (seal && seal.t[key] || key).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m));

  if (form.dataset.encrypted !== 'true') {
    // One submit per click: a second tap on a slow connection would otherwise count twice.
    form.addEventListener('submit', () => setTimeout(() => busy(true), 0));
  } else {
    let ready = false;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!ready || button.disabled) return;
      busy(true);
      const [answers, errors] = collect(new FormData(form));
      if (!Object.keys(errors).length && !Object.keys(answers).length) errors[0] = T('Je hebt nog niets ingevuld.');
      if (Object.keys(errors).length) { showErrors(errors); busy(false); return; }
      let sealed;
      try {
        sealed = await E.seal(seal.key, seal.survey, { v: 1, a: answers });
      } catch (error) {
        console.error('mijnenquete: answer encryption failed', error);
        showErrors({ 0: T('Niet verstuurd: je browser kon je antwoorden niet versleutelen. Ze staan nog op deze pagina. Probeer opnieuw. Blijft dit gebeuren, gebruik dan een recente browser.') });
        busy(false);
        return;
      }
      // Only the sealed answers leave this browser: a separate form, without the readable fields.
      const out = document.createElement('form');
      out.method = 'post';
      out.action = form.action;
      out.hidden = true;
      const add = (name, value) => { const i = document.createElement('input'); i.type = 'hidden'; i.name = name; i.value = value; out.append(i); };
      add('sealed', sealed);
      for (const name of ['k', 'website']) { const f = form.elements[name]; if (f) add(name, f.value); }
      document.body.append(out);
      out.submit();
    });
    if (sealBlock && E && E.canSeal) {
      try {
        seal = JSON.parse(sealBlock.textContent);
        // Exercise the real key and algorithms before allowing anyone to enter answers.
        await E.seal(seal.key, seal.survey, { v: 1, a: {} });
        ready = true;
        form.querySelector('[data-encrypted-fields]').disabled = false;
        form.hidden = false;
        document.getElementById('encryption-unavailable').hidden = true;
      } catch (error) {
        console.error('mijnenquete: browser encryption is unavailable', error);
      }
    }
  }

  window.addEventListener('pageshow', (event) => { if (event.persisted) busy(false); });

  /* The same checks as collect_answers() in src/surveys.php, and the same stored values. */
  function collect(data) {
    const answers = {};
    const errors = {};
    const strip = (s, max) => String(s || '').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').trim().slice(0, max);
    for (const q of seal.questions) {
      const name = `q[${q.id}]`;
      const raw = data.get(name);
      let value = null;
      let invalid = null;
      switch (q.type) {
        case 'multi': {
          const picked = data.getAll(name + '[]').map(Number).filter((i) => Number.isInteger(i) && i in q.choices).sort((a, b) => a - b);
          if (picked.length) value = [...new Set(picked)].map((i) => q.choices[i]);
          break;
        }
        case 'single': case 'dropdown':
          if (raw !== null && /^\d+$/.test(raw) && Number(raw) in q.choices) value = q.choices[Number(raw)];
          break;
        case 'yesno':
          if (raw === 'ja' || raw === 'nee') value = raw === 'ja' ? 'Ja' : 'Nee';
          break;
        case 'stars': case 'scale': {
          const [min, max] = q.type === 'stars' ? [1, 5] : [q.min, q.max];
          if (raw !== null && /^\d+$/.test(raw) && Number(raw) >= min && Number(raw) <= max) value = String(Number(raw));
          break;
        }
        case 'date': {
          const text = strip(raw, 10);
          if (text !== '') {
            const d = new Date(text + 'T00:00:00Z');
            if (/^\d{4}-\d{2}-\d{2}$/.test(text) && !isNaN(d) && d.toISOString().slice(0, 10) === text) value = text;
            else invalid = T('Kies een geldige datum.');
          }
          break;
        }
        case 'email': {
          const text = strip(raw, 190);
          if (text !== '') {
            if (/^[^\s@"(),:;<>[\]\\]+@[^\s@"(),:;<>[\]\\]+\.[^\s@"(),:;<>[\]\\.]{2,}$/.test(text)) value = text;
            else invalid = T('Vul een geldig e-mailadres in, zoals naam@voorbeeld.nl.');
          }
          break;
        }
        default: {
          const text = strip(raw, q.type === 'long' ? 5000 : 500);
          if (text !== '') value = text;
        }
      }
      if (invalid) errors[q.id] = invalid;
      else if (value === null && q.required) errors[q.id] = T('Deze vraag is verplicht.');
      else if (value !== null) answers[String(q.id)] = value;
    }
    return [answers, errors];
  }

  /* Errors shown the way the server shows them. */
  function showErrors(errors) {
    document.querySelectorAll('[data-client-error]').forEach((el) => el.remove());
    document.querySelectorAll('.sq-error').forEach((el) => el.classList.remove('sq-error'));
    document.querySelectorAll('[aria-invalid="true"]').forEach((el) => el.removeAttribute('aria-invalid'));
    const box = document.createElement('div');
    box.className = 'notice notice-error';
    box.setAttribute('role', 'alert');
    box.tabIndex = -1;
    box.dataset.clientError = '';
    const p = document.createElement('p');
    const n = Object.keys(errors).filter((k) => k !== '0').length;
    p.textContent = errors[0] || (n === 1 ? T('Nog niet verstuurd. Eén vraag heeft je aandacht nodig.') : T('Nog niet verstuurd. {n} vragen hebben je aandacht nodig.', { n }));
    box.append(p);
    form.before(box);
    let first = null;
    for (const [qid, message] of Object.entries(errors)) {
      if (qid === '0') continue;
      const control = form.querySelector(`[name="q[${qid}]"], [name="q[${qid}][]"]`);
      const item = control && control.closest('.sq');
      if (!item) continue;
      item.classList.add('sq-error');
      const err = document.createElement('p');
      err.className = 'error';
      err.dataset.clientError = '';
      err.textContent = message;
      item.querySelector('.sq-body').append(err);
      if (control.matches('input[type=text], input[type=email], input[type=date], textarea, select')) control.setAttribute('aria-invalid', 'true');
      first ??= item;
    }
    (first || box).scrollIntoView({ block: 'center' });
    const focus = first && first.querySelector('input, textarea, select');
    (focus || box).focus({ preventScroll: true });
  }
})();
