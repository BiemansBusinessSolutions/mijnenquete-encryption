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

**Passwords are not sent.** Every form that takes the account password (sign-in,
sign-up, reset, password change and password confirmations) sends only the login
value. The password fields arrive disabled, so a browser without JavaScript or Web
Crypto cannot submit them; `password.js` and `vault.js` enable them only once they
handle the form, and show an error instead of submitting when derivation fails. The
server accepts no password in place of a login value and has no server-side
derivation for new passwords. One exception remains: an account created before
browser-side derivation (`pw_v` 0) sends its password once, at its first sign-in,
so the server can verify and upgrade its stored hash. Such an account has no
encryption keys until after that upgrade. This removes accidental exposure, not
the trust limit below: the service still delivers the JavaScript that handles the
password.

## Recovery

A 160-bit random backup code derives a key using HKDF-SHA256, a random salt and
`mijnenquete-backup-code-v1`. It wraps a separate backup private key with AES-GCM,
authenticated to `mijnenquete-backup-v1:<backup public key>`. Owner private keys
are also sealed to the backup public key with info `mijnenquete-backup-v1` and
additional data `mijnenquete-key-v1:<owner public key>`.

Password changes rewrap keys in the browser. A password reset permits a new
key for new answers; old keys need the old password, backup code, or a retained
device unlock key. Losing all of these can make older answers inaccessible.

## What is kept about respondents

`src/respond.php` holds the whole server side of a respondent's visit.

- **IP address:** never stored. It is counted against floods as a keyed hash in a
  rate-limit row that expires with its window (at most an hour for answering).
- **Device cookie:** after answering, the browser receives one random 128-bit code.
  The server stores only a keyed hash per survey (`survey_devices`), without a time,
  to recognise "already answered". Accounts store a differently keyed hash of the
  devices they sign in on, with only the day (`user_devices`). Without the cookie
  itself these values cannot be matched to each other, across surveys, or to an
  answer. Rows written before 2026-11-19 used one hash for every survey; they can
  still show that one device answered several surveys, but no longer link to
  accounts.
- **Answer:** the sealed blob, the survey and the time it arrived. No device,
  address or account is stored with it.
- **Unlock token (`k`):** for a survey behind a password. It names the survey and a
  time, not a person; there are no personal invitation links.
- **Email address:** only for a survey limited to allowed email addresses (a paid
  feature). The address the respondent types is checked against the owner's list and
  then kept only as a keyed hash, different per survey: next to a one-time code for
  15 minutes (14 days for an invitation), and, once that address has answered,
  without a time and without an auto-increment key (`survey_answered_emails`), only to
  say "already answered". The unlock token for this mode names the survey, the hash
  and a time; it is never stored with the answer. So the operator can tell which
  allowed addresses answered, but not which answer is whose. The owner sees neither.
  Invitations and codes are delivered by Brevo (France), which receives the address
  and the code.

Outside this code: the web host and Cloudflare keep request logs (time, IP
address, requested path) under their own retention. Together with an answer's
arrival time, those logs can show which address submitted to which survey. A
signed-in respondent's session is also touched by the request. This is metadata
about who took part, not answer content.

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
