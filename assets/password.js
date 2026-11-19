/*
 * Signing in, signing up and choosing a new password, without the password leaving this browser.
 * The password is stretched here (e2e.js) into a login value, which is sent instead, and an unlock key,
 * which stays here so the owner's encryption keys open without asking again (vault.js).
 * The password fields come disabled from the server, so they are never submitted as typed. This file
 * enables them only once it has taken over the form; without it (no JavaScript, no Web Crypto) they stay
 * disabled and the page says why. When stretching fails, nothing is sent. The one exception is an account
 * from before (pw_v 0), whose first sign-in sends the password once so the server can upgrade its hash.
 */
(() => {
  const E = globalThis.MijnE2E;
  const block = document.getElementById('pw');
  const boot = block ? JSON.parse(block.textContent) : {};
  const T = (key) => (boot.t && boot.t[key]) || key;

  function hidden(form, name, value) {
    let input = form.querySelector(`input[type=hidden][name="${name}"]`);
    if (!input) {
      input = document.createElement('input');
      input.type = 'hidden';
      input.name = name;
      form.append(input);
    }
    input.value = value;
  }

  function busy(form, on) {
    const button = form.querySelector('button[type=submit]');
    if (!button) return;
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.disabled = on;
    button.textContent = on ? T('Even geduld…') : button.dataset.label;
  }

  /** The password rules. Only checked here: the server never gets the password to check. */
  function problem(password, notLike) {
    const n = [...password].length;
    if (n < 10) return T('Kies een wachtwoord van minstens 10 tekens.');
    if (new TextEncoder().encode(password).length > 200) return T('Kies een wachtwoord van hoogstens 200 tekens.');
    if (notLike.some((o) => o && o.toLowerCase() === password.toLowerCase())) return T('Kies een wachtwoord dat niet gelijk is aan je naam of e-mailadres.');
    if (/^(.)\1+$/u.test(password) || ['1234567890', 'wachtwoord123', 'password123', 'qwertyuiop'].includes(password.toLowerCase())) {
      return T('Dit wachtwoord is te makkelijk te raden. Kies een ander.');
    }
    return null;
  }

  const notLikeOf = (form) => [form.elements.username, form.elements.email].filter(Boolean).map((i) => i.value).concat(boot.notLike || []);

  /*
   * How hard the password is to guess, as 0 (weak), 1 (medium) or 2 (good). A rough guide for the
   * meter only: length counts most, then mixing kinds of characters or words; runs, repeats and
   * the usual suspects count against it. Anything the rules above turn down is weak.
   */
  function strength(password, notLike) {
    if (problem(password, notLike)) return 0;
    const n = [...password].length;
    const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^\w\s]/, /\s/].filter((re) => re.test(password)).length;
    let score = 1 + (n >= 14) + (n >= 18) + (kinds >= 3) + (password.trim().split(/\s+/).length >= 3);
    if (/(.)\1\1/u.test(password)) score--;
    if (/0123|1234|2345|3456|4567|5678|6789|abcd|qwert|azert|asdf|wachtwoord|password|welkom|enquete|survey/i.test(password)) score--;
    return score <= 1 ? 0 : score === 2 ? 1 : 2;
  }

  /** The meter under a new password: three bars, an icon and a line that says how it is doing. */
  const LEVELS = [
    { name: 'weak', label: 'Zwak', line: 'Zelfs een enquête met één vraag raadt dit.',
      icon: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>' },
    { name: 'medium', label: 'Redelijk', line: 'Op een schaal van 1 tot 5: een nette 3.',
      icon: '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>' },
    { name: 'good', label: 'Sterk', line: 'Uit onze enquête: 0 van de 10 hackers raadt dit.',
      icon: '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16.2 9.5"/>' },
  ];
  for (const form of document.querySelectorAll('form[data-pw-meter]')) {
    const input = form.elements.password;
    if (!input) continue;
    const meter = document.createElement('div');
    meter.className = 'pw-meter';
    meter.hidden = true;
    meter.innerHTML = '<svg class="pw-icon" viewBox="0 0 24 24" aria-hidden="true"></svg>'
      + '<span class="pw-bars" aria-hidden="true"><i></i><i></i><i></i></span>'
      + '<p class="pw-text" aria-live="polite"><b></b> <span></span></p>';
    input.closest('.field').append(meter);
    const icon = meter.querySelector('.pw-icon');
    let shown = -1;
    const update = () => {
      const level = input.value === '' ? -1 : strength(input.value, notLikeOf(form));
      if (level === shown) return;
      shown = level;
      meter.hidden = level < 0;
      if (level < 0) return;
      const L = LEVELS[level];
      meter.dataset.level = L.name;
      icon.innerHTML = L.icon;
      meter.querySelector('b').textContent = T(L.label);
      meter.querySelector('.pw-text span').textContent = T(L.line);
      // Restart the little pop each time the verdict changes.
      icon.classList.remove('pop');
      void icon.getBoundingClientRect();
      icon.classList.add('pop');
    };
    input.addEventListener('input', update);
    for (const other of [form.elements.username, form.elements.email]) if (other) other.addEventListener('input', update);
    update();
  }

  if (!E || !E.supported) return;

  const FAILED = 'Niet verstuurd: je wachtwoord kon in deze browser niet veilig worden voorbereid. Probeer het opnieuw.';

  /** From here on this file sends the form: the password fields may be typed in. */
  function takeOver(form) {
    for (const input of form.querySelectorAll('input[data-needs-crypto]')) {
      input.disabled = false;
      const note = input.closest('.field').querySelector('[data-crypto-unavailable]');
      if (note) note.hidden = true;
    }
  }

  /** Shown the way field() in _helpers.php shows a server error. */
  function fieldError(input, message) {
    const field = input.closest('.field');
    const id = input.id + '-error';
    let p = document.getElementById(id);
    if (!message) {
      if (p) p.remove();
      field.classList.remove('has-error');
      input.removeAttribute('aria-invalid');
      return;
    }
    if (!p) {
      p = document.createElement('p');
      p.className = 'error';
      p.id = id;
      field.append(p);
      input.setAttribute('aria-describedby', ((input.getAttribute('aria-describedby') || '') + ' ' + id).trim());
    }
    p.textContent = message;
    field.classList.add('has-error');
    input.setAttribute('aria-invalid', 'true');
    input.focus();
  }

  /** The password field stops being sent: from here on only the hidden fields carry what the server needs. */
  function send(form, input) {
    input.removeAttribute('name');
    form.submit();
  }

  const login = document.querySelector('form[data-pw="login"]');
  if (login) {
    takeOver(login);
    login.addEventListener('submit', async (event) => {
      event.preventDefault();
      const input = login.elements.password;
      busy(login, true);
      try {
        const body = new URLSearchParams({ csrf: login.elements.csrf.value, email: login.elements.email.value });
        const res = await fetch('/inloggen/zout', { method: 'POST', body, credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (!res.ok) throw new Error(String(res.status));
        const { salt, v } = await res.json();
        const d = await E.derive(input.value, salt);
        // Kept as "not confirmed" until a signed-in page sees that this was the right password (vault.js).
        // Without storage, signed-in pages ask for the password once instead.
        try { await E.store('p', salt, d.unlock); } catch { /* private window, storage blocked */ }
        if (v === 1) {
          hidden(login, 'password_auth', d.auth);
          send(login, input);
          return;
        }
        // An account from before: the server checks the password itself once, then stretches it with the same salt.
        login.submit();
      } catch {
        busy(login, false);
        fieldError(input, T(FAILED));
      }
    });
  }

  for (const form of document.querySelectorAll('form[data-pw="new"]')) {
    takeOver(form);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const input = form.elements.password;
      const why = problem(input.value, notLikeOf(form));
      fieldError(input, why);
      if (why) return;
      busy(form, true);
      try {
        const salt = E.newSalt();
        const d = await E.derive(input.value, salt);
        if (form.dataset.pwKeep !== undefined) { try { await E.store('p', salt, d.unlock); } catch { /* asked for later */ } }
        hidden(form, 'password_auth', d.auth);
        hidden(form, 'password_salt', salt);
        send(form, input);
      } catch {
        busy(form, false);
        fieldError(input, T(FAILED));
      }
    });
  }
})();
