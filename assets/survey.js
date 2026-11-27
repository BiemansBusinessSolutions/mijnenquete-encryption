/* Ordinary surveys work without scripts; encrypted surveys require browser encryption before filling in. */
(async () => {
  const form = document.querySelector('.survey form[novalidate]');
  const sealBlock = document.getElementById('seal');
  const flowBlock = document.getElementById('flow');
  const E = globalThis.MijnE2E;
  const S = globalThis.MijnSurvey;
  let seal = null;
  let flow = null; // {questions, links, t} when the survey branches; otherwise the page stays as it is
  let live = null;
  let shown = null;
  const T = (key, vars = {}) => (((seal || flow) && (seal || flow).t[key]) || key).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m));

  // Before the error summary below scrolls: questions that are not on the route go first.
  if (form && flowBlock && form.dataset.encrypted !== 'true') {
    try { startRoute(JSON.parse(flowBlock.textContent)); } catch (error) { console.error('mijnenquete: survey route unavailable', error); }
  }

  const summary = document.querySelector('[data-error-summary]');
  if (summary) {
    const first = document.querySelector('.sq-error');
    (first || summary).scrollIntoView({ block: 'center' });
    const control = first && first.querySelector('input, textarea, select');
    (control || summary).focus({ preventScroll: true });
  }

  if (!form) return;
  const button = form.querySelector('button[type=submit]');
  const label = button.textContent;
  const busy = (on) => { button.disabled = on; button.textContent = on ? (button.dataset.sending || label) : label; };

  if (form.dataset.encrypted !== 'true') {
    // One submit per click: a second tap on a slow connection would otherwise count twice.
    form.addEventListener('submit', () => setTimeout(() => busy(true), 0));
  } else {
    let ready = false;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!ready || button.disabled) return;
      busy(true);
      const [answers, errors, skipped] = S.collect(seal, new FormData(form));
      if (!Object.keys(errors).length && !Object.keys(answers).length) errors[0] = T('Je hebt nog niets ingevuld.');
      if (Object.keys(errors).length) { showErrors(errors); busy(false); return; }
      let sealed;
      // s: the questions off this respondent's route, left out when there are none (PROTOCOL.md).
      const payload = skipped.length ? { v: 1, a: answers, s: skipped } : { v: 1, a: answers };
      try {
        sealed = await E.seal(seal.key, seal.survey, payload);
      } catch (error) {
        console.error('mijnenquete: answer encryption failed', error);
        showErrors({ 0: T('Niet verstuurd: je browser kon je antwoorden niet versleutelen. Ze staan nog op deze pagina. Probeer opnieuw. Blijft dit gebeuren, gebruik dan een recente browser.') });
        busy(false);
        return;
      }
      // The same answers once more for each collaborator who may read them, by their position in the list the page
      // came with (no user ids on the page). A copy that fails, or that would make the post too large, is left out:
      // the answer still goes to the owner, and the owner's browser shares it with the collaborator later.
      const copies = [];
      let used = sealed.length;
      for (const reader of seal.readers) {
        let copy;
        try { copy = await E.seal(reader.public, seal.survey, payload); } catch (error) {
          console.error('mijnenquete: sealing for a collaborator failed', error);
          continue;
        }
        if (!S.copyFits(used, copy.length)) break;
        used += copy.length;
        copies.push([reader.index, copy]);
      }
      // Only the sealed answers leave this browser: a separate form, without the readable fields.
      const out = document.createElement('form');
      out.method = 'post';
      out.action = form.action;
      out.hidden = true;
      const add = (name, value) => { const i = document.createElement('input'); i.type = 'hidden'; i.name = name; i.value = value; out.append(i); };
      add('sealed', sealed);
      if (copies.length) {
        for (const [index, value] of copies) add('sealed_for[' + index + ']', value);
        add('readers_fp', String(seal.readersFp || ''));
      }
      for (const name of ['k', 'website']) { const f = form.elements[name]; if (f) add(name, f.value); }
      document.body.append(out);
      out.submit();
    });
    if (sealBlock && E && E.canSeal) {
      try {
        seal = JSON.parse(sealBlock.textContent);
        // Exercise the real key and algorithms before allowing anyone to enter answers.
        await E.seal(seal.key, seal.survey, { v: 1, a: {} });
        // A collaborator key that does not work here is dropped; the survey stays open for answers.
        const readers = [];
        const listed = Array.isArray(seal.readers) ? seal.readers : [];
        for (const [index, reader] of listed.entries()) {
          try { await E.seal(reader.public, seal.survey, { v: 1, a: {} }); readers.push({ index, public: reader.public }); } catch (error) {
            console.error('mijnenquete: a collaborator key is unusable', error);
          }
        }
        seal.readers = readers;
        ready = true;
        form.querySelector('[data-encrypted-fields]').disabled = false;
        if (seal.links) {
          try { startRoute(seal); } catch (error) { console.error('mijnenquete: survey route unavailable', error); }
        }
        form.hidden = false;
        document.getElementById('encryption-unavailable').hidden = true;
      } catch (error) {
        console.error('mijnenquete: browser encryption is unavailable', error);
      }
    }
  }

  window.addEventListener('pageshow', (event) => { if (event.persisted) busy(false); });

  /** Shows only the questions on the route, and follows every answer from now on. */
  function startRoute(data) {
    flow = data;
    live = document.createElement('div');
    live.className = 'sr';
    live.setAttribute('role', 'status');
    live.setAttribute('aria-live', 'polite');
    form.after(live);
    applyRoute();
    form.addEventListener('change', () => applyRoute());
    form.addEventListener('input', () => applyRoute());
  }

  /*
   * Off-route questions are hidden and inert but keep what was typed, so changing your mind back
   * loses nothing; collect() leaves them out. Visible questions are numbered 1, 2, 3 in order.
   */
  function applyRoute() {
    const items = form.querySelectorAll('.sq[data-q]');
    let skipped = [];
    // Their fields are disabled too: hidden and inert fields would still be posted, disabled ones are not.
    // Disabled fields are also missing from FormData, so a question that comes back onto the route
    // is read again once enabled; repeat until nothing changes (at most once per question).
    for (let round = 0; round <= items.length; round++) {
      skipped = S.collect(flow, new FormData(form))[2];
      let changed = false;
      for (const item of items) {
        const off = skipped.includes(Number(item.dataset.q));
        for (const control of item.querySelectorAll('input, select, textarea')) {
          if (control.disabled !== off) { control.disabled = off; changed = true; }
        }
      }
      if (!changed) break;
    }
    const before = shown;
    shown = 0;
    for (const item of items) {
      const off = skipped.includes(Number(item.dataset.q));
      if (off !== item.hidden) {
        item.hidden = off;
        item.inert = off;
        if (!off && before !== null) {
          item.classList.remove('sq-appear');
          void item.offsetWidth; // restart the fade when it appears again
          item.classList.add('sq-appear');
        }
      }
      if (!off) item.querySelector('.sq-n').textContent = String(++shown);
    }
    if (before !== null && shown > before) {
      const n = shown - before;
      const message = n === 1 ? T('Er is één vraag bijgekomen') : T('Er zijn {n} vragen bijgekomen', { n });
      // Emptied first, so the same message twice in a row is read out again.
      live.textContent = '';
      setTimeout(() => { live.textContent = message; }, 100);
    }
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
