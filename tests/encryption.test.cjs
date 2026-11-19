const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { runInNewContext } = require('node:vm');
const { webcrypto } = require('node:crypto');

function cryptoInBrowser() {
  const browser = { crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, btoa, atob };
  runInNewContext(readFileSync(join(__dirname, '../assets/e2e.js'), 'utf8'), browser);
  return browser.MijnE2E;
}

test('respondents can encrypt without IndexedDB; owners still need key storage', async () => {
  const E = cryptoInBrowser();
  assert.equal(E.canSeal, true);
  assert.equal(E.supported, false);
  const pair = await E.createKeyPair();
  const privateKey = await E.usable(pair.pkcs8);
  const sealed = await E.seal(pair.publicKey, 7, { v: 1, a: { 3: 'Only the owner reads this' } });
  assert.equal((await E.open(privateKey, 7, sealed)).a[3], 'Only the owner reads this');
  await assert.rejects(E.open(privateKey, 8, sealed));
  const bytes = Buffer.from(sealed, 'base64');
  bytes[bytes.length - 1] ^= 1;
  await assert.rejects(E.open(privateKey, 7, bytes.toString('base64')));
});

test('password and backup recovery open the same private key without sending unlock material', async () => {
  const E = cryptoInBrowser();
  const { auth, unlock } = await E.derive('Zomer in Zürich 2026!', '00112233445566778899aabbccddeeff');
  assert.equal(auth, '08d6507210e4d1d1c49578d4f8609bbffdfa160df585805ae0cd82aa4a517850');
  assert.equal(unlock.extractable, false);
  const pair = await E.createKeyPair();
  const wrapped = await E.wrapKey(unlock, pair.publicKey, pair.pkcs8);
  assert.deepEqual(await E.unwrapKey(unlock, pair.publicKey, wrapped), pair.pkcs8);
  const other = await E.derive('A different password', '00112233445566778899aabbccddeeff');
  await assert.rejects(E.unwrapKey(other.unlock, pair.publicKey, wrapped));
  const backup = await E.createBackup();
  const sealed = await E.backupSeal(backup.publicKey, pair.publicKey, pair.pkcs8);
  const backupPrivate = await E.openBackup(backup.code, backup.publicKey, backup.wrapped);
  assert.deepEqual(await E.backupOpen(backupPrivate, pair.publicKey, sealed), pair.pkcs8);
});
