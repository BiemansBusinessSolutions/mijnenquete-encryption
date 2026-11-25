# Mijn Enquete: inspectable encryption

This repository contains an automated, allowlisted export from the source used
by [mijnenquete.nl](https://mijnenquete.nl). It is not a second implementation
or a standalone survey service. The exported material is MIT licensed; this
does not license the rest of the application.

## What is here

- `assets/e2e.js`: Web Crypto, password derivation, private-key wrapping and backup recovery.
- `assets/survey.js`: capability check, showing only the questions on the respondent's route,
  and encrypted submission.
- `assets/survey-collect.js` and `assets/flow.js`: respondent validation and the route through a
  branching survey, which decides which answers are sealed and which questions are listed as skipped.
- `assets/password.js` and `assets/vault.js`: password stretching for every password form,
  key lifecycle, local decryption, results and CSV export. Account password fields arrive
  disabled and are enabled only by these files, so the password itself is never submitted.
- `src/e2e.php`: formats, storage of ciphertext/locked keys, and the server acceptance
  policy: `encrypted_submission_problem()` rejects every encrypted-survey submission
  that is not a single well-formed sealed blob, before anything is stored.
- `src/respond.php`: everything a respondent's visit touches on the server: the
  submission handler, the "already answered" device cookie, IP-address handling for
  rate limits, and the unlock token of a survey behind a password.
- `src/pages/encryption.php`: authenticated key and ciphertext endpoints.
- `src/views/survey.php`: the respondent form, hidden and disabled by default for
  encrypted surveys until a trial encryption succeeds.
- `tests/encryption.test.cjs`: runnable checks using the actual browser crypto file.
- `tests/survey-collect.test.cjs`: runnable checks that only answers on the route are sealed.

These are complete source files, not rewritten examples.

The PHP files depend on the private application's helpers and database; this
export is not a runnable PHP application or a complete authentication review.

## Verify a release

`manifest.json` records the source commit and SHA-256 of every exported file.
Published snapshots are tagged `source-<full-source-commit>`. The publishing job
checks the deployment acknowledgement against that commit before exporting it.
This is a release record, not an independent attestation of what every visitor
received, and it can lag a deployment if publication fails.

1. Select the corresponding release tag, not a moving branch.
2. With Node.js 22 or newer, run `node --test tests/encryption.test.cjs`.
3. Download the JavaScript actually loaded by your browser (the Network tab shows
   the URLs, including any cache query). Compare SHA-256 with that release's
   manifest. Do not copy/paste the script: that can change its bytes or line endings.
4. On a test survey you own, submit a synthetic answer and inspect the request.
   With encryption enabled it must contain `sealed`, not readable `q[...]` fields.
5. Test with JavaScript disabled: an encrypted form must be unavailable. A failed
   encryption operation must not submit the ordinary form.

For example, hash a downloaded file with `sha256sum` on Linux or
`Get-FileHash -Algorithm SHA256` in PowerShell. A mismatch needs investigation:
caching, a different release, or changed delivery can all explain it.

## Guarantees and limits

Encryption is on by default for new surveys and available on every plan.
Owners can turn it off. For encrypted surveys, the provided client encrypts
answers before sending them; the server rejects readable answer submissions.
This does not prevent an arbitrary client from sending arbitrary bytes to a
server, nor does the server verify ciphertext contents that it cannot decrypt.

Questions, survey titles, response counts and timestamps are not end-to-end
encrypted. Read [PROTOCOL.md](PROTOCOL.md) for key handling, password fallbacks,
old responses and the browser-delivery trust boundary.

**Public source is not proof of security or evidence of an independent audit.**
No independent audit is claimed by this publication.

Report issues privately as described in [SECURITY.md](SECURITY.md), or ask
questions at [veiligheid@mijnenquete.nl](mailto:veiligheid@mijnenquete.nl).
