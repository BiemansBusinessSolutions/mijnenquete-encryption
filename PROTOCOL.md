# Encryption protocol and trust boundaries

This describes version 1 as implemented in the exported source, not a new
cryptographic standard. Review the composition and integration, not only the
names of the primitives.

## Answers

The owner creates an ECDH P-256 key pair in the browser. The respondent receives
its public key from the service. For each answer submission the respondent:

1. Generates a fresh ephemeral ECDH P-256 key pair and derives a 256-bit shared secret.
2. Derives an AES-256-GCM key using HKDF-SHA256, with the 65-byte ephemeral public
   point as salt and `mijnenquete-answers-v1` as the info string.
3. Encrypts UTF-8 JSON `{v:1,a:{"<question id>":"text or array"}}` with a random
   12-byte IV and additional authenticated data `mijnenquete-answers:<survey id>`.
4. Sends base64 of `0x01 | ephemeral point (65) | IV (12) | ciphertext | tag (16)`.

The owner decrypts in the browser. Survey binding rejects ciphertext moved
between survey IDs, but is not sender authentication or replay prevention.
The server validates the envelope, not its authenticity or answer contents.

Encrypted forms start hidden and disabled. A local trial encryption exercises
the public key and algorithms before enabling input. Respondents need JavaScript
and Web Crypto in a secure context; they do not need IndexedDB. No browser
encryption means no submission. A missing owner key also blocks submission.
Runtime failures preserve input and show an error, never a plaintext fallback.

## Passwords and private keys

PBKDF2-SHA256 (600,000 iterations, account-specific 16-byte salt) derives a
256-bit master. HKDF-SHA256 with empty salt and separate info strings derives:

- `mijnenquete-login-v1`: a login value sent to the server and password-hashed there.
- `mijnenquete-unlock-v1`: an AES-256-GCM key used locally to wrap the private key.

A wrapped private key is JSON `{v:1,iv,ct}`. Its authenticated data is
`mijnenquete-key-v1:<public key>`. The browser retains non-extractable unlock keys
in IndexedDB until sign-out. Non-extractable does not stop same-origin malicious
JavaScript from using a key.

The server adds an outer AES-GCM layer using its own application key to the
already-wrapped private keys. That extra layer is defense in depth, not the
end-to-end protection; its key is not published.

**Authentication fallback still exists:** without supported browser scripting,
login/password forms may send the account password over HTTPS and the server
derives the login value. Legacy account upgrades can also send the password.
Because the password derives the unlock key, this is a trust limitation: do not
interpret this design as the server being technically unable to obtain unlock
material under all login scenarios. Changing respondent submission does not
remove that separate authentication behaviour.

## Recovery

A 160-bit random backup code derives a key using HKDF-SHA256, a random salt and
`mijnenquete-backup-code-v1`. It wraps a separate backup private key with AES-GCM,
authenticated to `mijnenquete-backup-v1:<backup public key>`. Owner private keys
are also sealed to the backup public key with info `mijnenquete-backup-v1` and
additional data `mijnenquete-key-v1:<owner public key>`.

Password changes rewrap keys in the browser. A password reset permits a new
key for new answers; old keys need the old password, backup code, or a retained
device unlock key. Losing all of these can make older answers inaccessible.

## What publication cannot prove

- The service supplies both JavaScript and recipient public keys. Modified
  delivery, XSS, compromised endpoints or a malicious server can defeat the
  intended flow. This is not independently authenticated key transparency.
- Hash comparisons describe sampled bytes; a manifest on the same infrastructure
  cannot exclude targeted delivery of different bytes.
- Questions, titles and response metadata remain visible to the service.
  Decrypted CSV exports and owner devices need their own protection.
- Owners can disable encryption. Previously unencrypted answers remain readable;
  previously server-encrypted answers are not retroactively made browser-E2E.
- These classical primitives are not a post-quantum claim. This repository
  claims neither formal proof nor an independent audit.
