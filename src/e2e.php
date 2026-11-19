<?php
declare(strict_types=1);

/*
 * End-to-end encryption of answers. Only the survey owner can read what respondents send.
 *
 * The owner's key pair (ECDH P-256) is made in their browser (assets/vault.js), the first time they are
 * signed in. The public key comes here (user_keys.public_key). The private key comes here only locked:
 * with the unlock key that the browser derives from the owner's password at sign-in (see src/auth.php:
 * the server gets a different value derived from the same password, never the password or the unlock key),
 * and, when the owner made one, sealed for their backup key, whose private half is locked with a backup
 * code that only the owner has. Here each locked copy is sealed once more with APP_KEY (e2e_store), so a
 * copy of the database alone is not even enough to try passwords against.
 *
 * Signing in with the password is all the owner does: the browser keeps the unlock key (non-extractable,
 * IndexedDB) until they sign out, and opens the private key when answers are shown.
 *
 * A respondent's browser encrypts the answers for the owner's public key before sending them
 * (assets/survey.js). An encrypted survey accepts only sealed answers. Without browser encryption
 * the form stays disabled; there is no server-side encryption fallback. The owner's browser decrypts
 * the sealed answers (responses.sealed) to show the results.
 *
 * Sealed answers, version 1, base64 of:
 *   0x01 | ephemeral public key (65 bytes, uncompressed P-256 point) | IV (12) | AES-256-GCM ciphertext | tag (16)
 * The AES key is HKDF-SHA256 of the ECDH secret (the x-coordinate), salt the ephemeral public key,
 * info E2E_INFO. The additional data names the survey, so sealed answers cannot be moved to another one.
 * The plaintext is JSON: {"v":1,"a":{"<question id>":"text" or ["choice", …]}}, values as collect_answers() stores them.
 *
 * A locked private key (user_keys.wrap): JSON {"v":1,"iv","ct"}, AES-256-GCM with the unlock key, additional
 * data "mijnenquete-key-v1:<public key>". Sealed for the backup key (user_keys.backup): the format above
 * with info "mijnenquete-backup-v1" and that same additional data. The backup key's private half
 * (users.backup_wrapped): JSON {"v":1,"salt","iv","ct"}, AES-256-GCM with HKDF-SHA256 of the 20-byte
 * backup code, additional data "mijnenquete-backup-v1:<backup public key>".
 */

const E2E_VERSION = 1;
const E2E_INFO = 'mijnenquete-answers-v1';
/** Sealed answers larger than this are refused: 100 long answers fit easily, a flood does not. */
const E2E_MAX_SEALED = 4_000_000;
/** The most a locked private key, or a sealed one, takes as the browser sends it. */
const E2E_MAX_WRAPPED = 2000;

function e2e_aad(int $surveyId): string
{
    return 'mijnenquete-answers:' . $surveyId;
}

/** The owner's keys, oldest first, with what they are locked with opened up to what the browser needs. */
function e2e_keys(int $userId): array
{
    $out = [];
    foreach (rows('SELECT id, public_key, wrap, wrap_salt, backup, created_at FROM user_keys WHERE user_id = ? ORDER BY id', [$userId]) as $k) {
        $out[] = ['id' => (int)$k['id'], 'public' => $k['public_key'], 'salt' => $k['wrap_salt'], 'created' => (int)$k['created_at'],
            'wrap' => e2e_unstore($k['wrap'], $userId), 'backup' => $k['backup'] === null ? null : e2e_unstore($k['backup'], $userId)];
    }
    return $out;
}

/** The key new answers are sealed for: the owner's newest. */
function e2e_current_key(int $userId): ?array
{
    static $cache = [];
    if (!array_key_exists($userId, $cache)) {
        $k = row('SELECT id, public_key FROM user_keys WHERE user_id = ? ORDER BY id DESC LIMIT 1', [$userId]);
        $cache[$userId] = $k ? ['id' => (int)$k['id'], 'public' => $k['public_key']] : null;
    }
    return $cache[$userId];
}

function e2e_public_key(array $user): ?string
{
    return e2e_current_key((int)$user['id'])['public'] ?? null;
}

/** Encryption is a requirement, even when the owner's key is not available yet. */
function survey_encrypted(array $survey): bool
{
    return (int)($survey['e2e'] ?? 0) === 1;
}

function encrypted_submission_problem(array $post, ?array $ownerKey): ?string
{
    if ($ownerKey === null) return t('Deze enquête kan nog geen versleutelde antwoorden ontvangen. Vraag de maker om in te loggen en de versleuteling klaar te zetten.');
    if (array_key_exists('q', $post) || !isset($post['sealed'])) {
        return t('Niet verstuurd: deze enquête accepteert alleen antwoorden die op jouw apparaat zijn versleuteld. Zet JavaScript aan of open de link in een recente browser.');
    }
    if (!is_string($post['sealed']) || !sealed_ok(trim($post['sealed']))) {
        return t('Je antwoorden konden niet worden versleuteld. Vernieuw de pagina en probeer het opnieuw.');
    }
    return null;
}

/**
 * Locked key material as kept in the database: sealed once more with APP_KEY, for this account only.
 * Without APP_KEY (which is not in the database or its backups) nobody can even start guessing passwords.
 */
function e2e_store(string $plain, int $userId): string
{
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', app_key('e2e-store'), OPENSSL_RAW_DATA, $iv, $tag, 'user:' . $userId, 16);
    return base64_encode($iv . $tag . $ct);
}

function e2e_unstore(string $stored, int $userId): ?string
{
    $raw = base64_decode($stored, true);
    if ($raw === false || strlen($raw) < 29) return null;
    $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', app_key('e2e-store'), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16), 'user:' . $userId);
    return $plain === false ? null : $plain;
}

/** A short, readable fingerprint of a public key, so an owner can recognise their own key. */
function e2e_fingerprint(string $spkiB64): string
{
    $der = base64_decode($spkiB64, true);
    return implode(' ', str_split(strtoupper(substr(hash('sha256', $der === false ? '' : $der), 0, 16)), 4));
}

function e2e_pem(string $spkiB64): string
{
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split($spkiB64, 64, "\n") . "-----END PUBLIC KEY-----\n";
}

/** A P-256 public key in SPKI form, base64, as Web Crypto exports it; null when it is anything else. */
function e2e_valid_public_key(string $spkiB64): ?string
{
    $spkiB64 = trim($spkiB64);
    if ($spkiB64 === '' || strlen($spkiB64) > 200) return null;
    $der = base64_decode($spkiB64, true);
    if ($der === false || strlen($der) !== 91) return null;
    $key = @openssl_pkey_get_public(e2e_pem($spkiB64));
    if ($key === false) return null;
    $d = openssl_pkey_get_details($key);
    if (($d['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ($d['ec']['curve_name'] ?? '') !== 'prime256v1') return null;
    return base64_encode($der);
}

/**
 * Locked key material as the browser sends it: 'wrap' (a private key locked with the unlock key) or
 * 'code' (the backup key's private half, locked with the backup code) as small JSON, or 'sealed' (a
 * private key sealed for the backup key). Only the shape is checked; the server cannot open it, which is the point.
 */
function e2e_valid_wrapped(string $value, string $kind): ?string
{
    if ($value === '' || strlen($value) > E2E_MAX_WRAPPED) return null;
    if ($kind === 'sealed') return sealed_ok($value) ? $value : null;
    $w = json_decode($value, true);
    if (!is_array($w) || ($w['v'] ?? null) !== 1) return null;
    $b64 = fn(string $k, int $min, int $max): bool => is_string($w[$k] ?? null)
        && ($raw = base64_decode($w[$k], true)) !== false && strlen($raw) >= $min && strlen($raw) <= $max;
    if (!$b64('iv', 12, 12) || !$b64('ct', 100, 400)) return null;
    $out = ['v' => 1];
    if ($kind === 'code') {
        if (!$b64('salt', 16, 32)) return null;
        $out['salt'] = $w['salt'];
    }
    return json_encode($out + ['iv' => $w['iv'], 'ct' => $w['ct']], JSON_UNESCAPED_SLASHES);
}

/** A list {key id: value} posted as JSON in $field, each value checked as e2e_valid_wrapped() $kind. */
function e2e_posted_list(string $field, string $kind): array
{
    $list = json_decode((string)($_POST[$field] ?? ''), true);
    $out = [];
    if (!is_array($list) || count($list) > 100) return $out;
    foreach ($list as $id => $value) {
        if (is_string($value) && ($v = e2e_valid_wrapped($value, $kind)) !== null && ctype_digit((string)$id)) $out[(int)$id] = $v;
    }
    return $out;
}

/**
 * Keys the browser locked again, for the password whose salt is $toSalt. Only keys still locked with
 * another password ($fromSalt, or any other when null) change, so a key that opens now is never overwritten.
 */
function e2e_relock(int $userId, array $wraps, string $toSalt, ?string $fromSalt = null): int
{
    $n = 0;
    foreach ($wraps as $id => $wrap) {
        $n += q('UPDATE user_keys SET wrap = ?, wrap_salt = ? WHERE id = ? AND user_id = ? AND ' . ($fromSalt === null ? 'wrap_salt <> ?' : 'wrap_salt = ?'),
            [e2e_store($wrap, $userId), $toSalt, $id, $userId, $fromSalt ?? $toSalt])->rowCount();
    }
    return $n;
}

/** Sealed answers from a respondent's browser: the right version and sizes. Their content only the owner can check. */
function sealed_ok(string $sealed): bool
{
    if ($sealed === '' || strlen($sealed) > E2E_MAX_SEALED) return false;
    $raw = base64_decode($sealed, true);
    return $raw !== false && strlen($raw) >= 1 + 65 + 12 + 16 + 10 && ord($raw[0]) === E2E_VERSION && $raw[1] === "\x04";
}

/** Question ids whose answer is a list (multiple choice), stored as JSON text by collect_answers(). */
function multi_ids(array $questions): array
{
    $ids = [];
    foreach ($questions as $q) if ($q['type'] === 'multi') $ids[(int)$q['id']] = true;
    return $ids;
}

function store_sealed_response(int $surveyId, string $sealed, int $keyId): void
{
    q('INSERT INTO responses (survey_id, created_at, sealed, key_id) VALUES (?, ?, ?, ?)', [$surveyId, time(), $sealed, $keyId]);
}

/** Answers to read in the owner's browser: sealed ones as they are, older plain ones as values. */
function survey_response_data(int $surveyId, array $questions): array
{
    $multi = multi_ids($questions);
    $out = [];
    $plain = [];
    foreach (rows('SELECT a.response_id, a.question_id, a.value FROM answers a JOIN responses r ON r.id = a.response_id WHERE r.survey_id = ?', [$surveyId]) as $a) {
        $plain[(int)$a['response_id']][(string)$a['question_id']] = $a['value'];
    }
    foreach (rows('SELECT id, created_at, sealed, key_id FROM responses WHERE survey_id = ? ORDER BY id DESC', [$surveyId]) as $r) {
        $item = ['id' => (int)$r['id'], 'at' => (int)$r['created_at']];
        if ($r['sealed'] !== null) {
            $item['sealed'] = $r['sealed'];
            $item['key'] = $r['key_id'] === null ? null : (int)$r['key_id'];
        } else {
            $a = [];
            foreach ($plain[(int)$r['id']] ?? [] as $qid => $value) {
                $a[$qid] = isset($multi[(int)$qid]) ? array_values(json_decode($value, true) ?: []) : $value;
            }
            $item['answers'] = (object)$a;
        }
        $out[] = $item;
    }
    return $out;
}

/** Whether results must be read in the browser: the survey is encrypted now, or was when answers came in. */
function survey_has_sealed(array $survey): bool
{
    return (int)($survey['e2e'] ?? 0) === 1 || (bool)val('SELECT 1 FROM responses WHERE survey_id = ? AND sealed IS NOT NULL LIMIT 1', [$survey['id']]);
}
