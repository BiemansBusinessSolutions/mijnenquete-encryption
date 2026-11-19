/*
 * End-to-end encryption in the browser (Web Crypto). Shared by survey.js (a respondent seals answers),
 * password.js (signing in and choosing a password) and vault.js (the owner's keys). The formats are
 * described in src/e2e.php and src/auth.php. Encrypted answers never fall back to server-side encryption.
 */
(() => {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const EC = { name: 'ECDH', namedCurve: 'P-256' };
  const ANSWERS_INFO = 'mijnenquete-answers-v1';
  const BACKUP_INFO = 'mijnenquete-backup-v1';
  const CODE_INFO = enc.encode('mijnenquete-backup-code-v1');
  const LOGIN_INFO = enc.encode('mijnenquete-login-v1');
  const UNLOCK_INFO = enc.encode('mijnenquete-unlock-v1');
  const PW_ROUNDS = 600000;
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const EMPTY = new Uint8Array(0);

  const b64 = (buf) => {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));
  const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

  async function hkdfKey(ikm, salt, info, usages) {
    const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, { name: 'AES-GCM', length: 256 }, false, usages);
  }

  /* --- The password --------------------------------------------------------
   * Stretched here with the account's salt, then split in two: the login value goes to the server in
   * place of the password; the unlock key stays in this browser and opens the owner's encryption keys. */

  const newSalt = () => hex(random(16));

  async function derive(password, saltHex) {
    const pw = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const master = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: PW_ROUNDS }, pw, 256);
    const base = await subtle.importKey('raw', master, 'HKDF', false, ['deriveBits', 'deriveKey']);
    const auth = hex(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: EMPTY, info: LOGIN_INFO }, base, 256));
    const unlock = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: EMPTY, info: UNLOCK_INFO }, base,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return { auth, unlock };
  }

  /* --- Sealing for a public key ----------------------------------------------
   * 0x01 | ephemeral public key (65) | IV (12) | AES-256-GCM ciphertext and tag. */

  async function sealBytes(publicKeyB64, info, aad, bytes) {
    const owner = await subtle.importKey('spki', unb64(publicKeyB64), EC, false, []);
    const eph = await subtle.generateKey(EC, false, ['deriveBits']);
    const ephRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
    const secret = await subtle.deriveBits({ name: 'ECDH', public: owner }, eph.privateKey, 256);
    const key = await hkdfKey(secret, ephRaw, enc.encode(info), ['encrypt']);
    const iv = random(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes));
    const out = new Uint8Array(1 + 65 + 12 + ct.length);
    out[0] = 1;
    out.set(ephRaw, 1);
    out.set(iv, 66);
    out.set(ct, 78);
    return b64(out);
  }

  async function openBytes(privateKey, info, aad, sealedB64) {
    const raw = unb64(sealedB64);
    if (raw[0] !== 1 || raw.length < 1 + 65 + 12 + 16) throw new Error('unknown format');
    const ephPub = await subtle.importKey('raw', raw.slice(1, 66), EC, false, []);
    const secret = await subtle.deriveBits({ name: 'ECDH', public: ephPub }, privateKey, 256);
    const key = await hkdfKey(secret, raw.slice(1, 66), enc.encode(info), ['decrypt']);
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(66, 78), additionalData: enc.encode(aad) }, key, raw.slice(78)));
  }

  /* --- Answers ------------------------------------------------------------- */

  const answersAad = (surveyId) => 'mijnenquete-answers:' + surveyId;

  /** Seal {v:1, a:{…}} for the owner's public key (SPKI, base64). */
  const seal = (publicKeyB64, surveyId, payload) =>
    sealBytes(publicKeyB64, ANSWERS_INFO, answersAad(surveyId), enc.encode(JSON.stringify(payload)));

  /** Open sealed answers with the owner's private key. Throws when they were not sealed for this key and survey. */
  async function open(privateKey, surveyId, sealedB64) {
    return JSON.parse(dec.decode(await openBytes(privateKey, ANSWERS_INFO, answersAad(surveyId), sealedB64)));
  }

  /* --- The owner's keys ---------------------------------------------------- */

  async function fingerprint(publicKeyB64) {
    const hash = new Uint8Array(await subtle.digest('SHA-256', unb64(publicKeyB64)));
    return hex(hash.slice(0, 8)).toUpperCase().match(/.{4}/g).join(' ');
  }

  const keyAad = (publicKeyB64) => enc.encode('mijnenquete-key-v1:' + publicKeyB64);

  async function createKeyPair() {
    const pair = await subtle.generateKey(EC, true, ['deriveBits']);
    return {
      publicKey: b64(await subtle.exportKey('spki', pair.publicKey)),
      pkcs8: new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey)),
    };
  }

  /** A private key locked with an unlock key (from derive). */
  async function wrapKey(unlock, publicKeyB64, pkcs8) {
    const iv = random(12);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: keyAad(publicKeyB64) }, unlock, pkcs8);
    return JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) });
  }

  /** The private key's bytes; throws when this unlock key does not open it. */
  async function unwrapKey(unlock, publicKeyB64, wrapJson) {
    const w = JSON.parse(wrapJson);
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(w.iv), additionalData: keyAad(publicKeyB64) }, unlock, unb64(w.ct)));
  }

  const usable = (pkcs8) => subtle.importKey('pkcs8', pkcs8, EC, false, ['deriveBits']);

  /* --- The backup key -------------------------------------------------------
   * A key pair of its own. Every encryption key is also sealed for its public half, so the backup code,
   * which opens the private half, opens them all, also keys made after a password reset. */

  function codeText(bytes) {
    let bits = 0, value = 0, out = '';
    for (const b of bytes) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out.match(/.{1,4}/g).join('-');
  }

  /** What someone typed as a backup code, back to its 20 bytes; null when it cannot be one. */
  function codeBytes(text) {
    const clean = String(text).toUpperCase().replace(/0/g, 'O').replace(/1/g, 'I').replace(/8/g, 'B').replace(/[^A-Z2-7]/g, '');
    if (clean.length !== 32) return null;
    const out = [];
    let bits = 0, value = 0;
    for (const c of clean) {
      value = (value << 5) | B32.indexOf(c);
      bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  const backupAad = (backupPublic) => enc.encode(BACKUP_INFO + ':' + backupPublic);

  /** A new backup key: the code to show once, its public key and its private key locked with the code. */
  async function createBackup() {
    const pair = await createKeyPair();
    const code = random(20), salt = random(16), iv = random(12);
    const key = await hkdfKey(code, salt, CODE_INFO, ['encrypt']);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: backupAad(pair.publicKey) }, key, pair.pkcs8);
    return { code: codeText(code), publicKey: pair.publicKey, wrapped: JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) }) };
  }

  /** The backup key's private half, from the code; throws when the code does not open it. */
  async function openBackup(text, backupPublic, wrappedJson) {
    const code = codeBytes(text);
    if (!code) throw new Error('not a code');
    const w = JSON.parse(wrappedJson);
    const key = await hkdfKey(code, unb64(w.salt), CODE_INFO, ['decrypt']);
    return usable(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(w.iv), additionalData: backupAad(backupPublic) }, key, unb64(w.ct)));
  }

  const backupSeal = (backupPublic, publicKeyB64, pkcs8) => sealBytes(backupPublic, BACKUP_INFO, 'mijnenquete-key-v1:' + publicKeyB64, pkcs8);
  const backupOpen = (backupPrivate, publicKeyB64, sealed) => openBytes(backupPrivate, BACKUP_INFO, 'mijnenquete-key-v1:' + publicKeyB64, sealed);

  /* --- Unlock keys on this device -------------------------------------------
   * Kept in IndexedDB as non-extractable CryptoKeys, by the salt of the password they come from: pages can
   * use them, nobody can read them out. 'p' is one from a sign-in that is not confirmed yet, 'w' one that
   * is. Signing out removes them all (theme.js). */

  const DB = 'mijnenquete-sleutels';

  /** The database, at least version 2 and with its store, even when something else made it without one. */
  function db(version = 2) {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, version);
      req.onupgradeneeded = () => {
        if (req.result.objectStoreNames.contains('keys')) req.result.deleteObjectStore('keys');
        req.result.createObjectStore('keys');
      };
      req.onsuccess = () => {
        const d = req.result;
        if (d.objectStoreNames.contains('keys')) { resolve(d); return; }
        const next = d.version + 1;
        d.close();
        db(next).then(resolve, reject);
      };
      req.onerror = () => {
        // Already at a higher version than asked for: open it as it is.
        if (req.error && req.error.name === 'VersionError') { const r = indexedDB.open(DB); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); }
        else reject(req.error);
      };
    });
  }

  async function tx(mode, fn) {
    const d = await db();
    try {
      return await new Promise((resolve, reject) => {
        const t = d.transaction('keys', mode);
        const req = fn(t.objectStore('keys'));
        t.oncomplete = () => resolve(req && req.result);
        t.onerror = () => reject(t.error);
      });
    } finally {
      d.close();
    }
  }

  const store = (kind, salt, key) => tx('readwrite', (s) => s.put(key, kind + ':' + salt));
  const remove = (kind, salt) => tx('readwrite', (s) => s.delete(kind + ':' + salt));
  async function recall(kind, salt) {
    try { return (await tx('readonly', (s) => s.get(kind + ':' + salt))) || null; } catch { return null; }
  }

  function forgetAll() {
    return new Promise((resolve) => {
      try {
        const req = indexedDB.deleteDatabase(DB);
        req.onsuccess = req.onerror = req.onblocked = () => resolve();
      } catch { resolve(); }
    });
  }

  globalThis.MijnE2E = {
    canSeal: !!subtle,
    supported: !!subtle && typeof indexedDB !== 'undefined',
    newSalt, derive, seal, open, fingerprint, createKeyPair, wrapKey, unwrapKey, usable,
    createBackup, openBackup, backupSeal, backupOpen, codeBytes, store, remove, recall, forgetAll,
  };
})();
