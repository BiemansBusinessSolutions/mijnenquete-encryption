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
        return t('Niet verstuurd: deze enquête neemt alleen antwoorden aan die op jouw apparaat op slot zijn gedaan. Open de link in een recente browser, zoals Firefox, Chrome, Edge of Safari.');
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

/**
 * The results-collaborators new answers are also sealed for, each with their newest key. Built from survey_readers(),
 * so the copies and the names respondents are shown always agree; a reader without a key yet gets no copy.
 * @return list<array{user: int, key: int, public: string}>
 */
function reader_keys(int $surveyId): array
{
    $out = [];
    foreach (survey_readers($surveyId) as $r) {
        if ($k = e2e_current_key($r['user_id'])) $out[] = ['user' => $r['user_id'], 'key' => $k['id'], 'public' => $k['public']];
    }
    return $out;
}

/**
 * A short, opaque mark of the reader list in its order (user and key ids), carried by the #seal block and posted back,
 * so a list that changed between page load and submit is noticed without the page showing anyone's user id.
 */
function readers_fingerprint(int $surveyId, array $readers): string
{
    $ids = array_map(fn($r) => (int)$r['user'] . ':' . (int)$r['key'], $readers);
    return substr(hash_hmac('sha256', $surveyId . '|' . implode(',', $ids), app_key('readers')), 0, 16);
}

/**
 * The collaborator copies worth keeping from a post's sealed_for[<position>]: the position is the reader's index in
 * $readers, the list as computed again for this post. If that list is not the one the page was built with (the posted
 * fingerprint differs), every copy is dropped; the owner's back-fill brings them later. Copies that do not look sealed
 * are dropped too, without a word: the answer itself never fails over a copy.
 * @return list<array{user: int, key: int, sealed: string}>
 */
function accept_reader_seals(mixed $posted, mixed $fingerprint, array $readers, int $surveyId): array
{
    if (!is_array($posted) || !is_string($fingerprint) || !hash_equals(readers_fingerprint($surveyId, $readers), $fingerprint)) return [];
    $out = [];
    foreach (array_values($readers) as $i => $r) {
        $v = $posted[$i] ?? null;
        if (is_string($v) && sealed_ok(trim($v))) $out[] = ['user' => (int)$r['user'], 'key' => (int)$r['key'], 'sealed' => trim($v)];
    }
    return $out;
}

/** The answer sealed for the owner, and its copies for collaborators, all or nothing. */
function store_sealed_response(int $surveyId, string $sealed, int $keyId, array $copies = []): void
{
    $pdo = db();
    $pdo->beginTransaction();
    try {
        q('INSERT INTO responses (survey_id, created_at, sealed, key_id) VALUES (?, ?, ?, ?)', [$surveyId, time(), $sealed, $keyId]);
        $rid = (int)$pdo->lastInsertId();
        foreach ($copies as $c) {
            // IGNORE: a collaborator whose account is deleted this very moment must not cost the respondent their answer.
            q('INSERT IGNORE INTO response_seals (response_id, user_id, key_id, sealed) VALUES (?, ?, ?, ?)', [$rid, $c['user'], $c['key'], $c['sealed']]);
        }
        $pdo->commit();
    } catch (Throwable $ex) {
        $pdo->rollBack();
        throw $ex;
    }
}

/**
 * The answers worth storing from the owner's back-fill for one collaborator ($copies: response id => sealed): only while
 * that member has the results, only for the member's current key, only for sealed responses of this survey
 * ($surveyResponseIds), only what looks sealed. With the existing answers shared any of them; with only new answers
 * just those after results_since (an answer that arrived before acceptance, or from a page loaded earlier, has no
 * copy yet and is brought this way).
 * @return array<int, string>
 */
function backfill_accepts(array $copies, array $member, int $currentKeyId, int $postedKey, array $surveyResponseIds): array
{
    if ((int)($member['results'] ?? 0) !== 1) return [];
    if ($postedKey !== $currentKeyId) return [];
    [$low] = backfill_window($member, 0);
    $ofSurvey = array_flip(array_map('intval', $surveyResponseIds));
    $out = [];
    foreach ($copies as $id => $v) {
        if (!is_int($id) && !ctype_digit((string)$id)) continue;
        $id = (int)$id;
        if (!isset($ofSurvey[$id]) || $id <= $low || !is_string($v) || !sealed_ok(trim($v))) continue;
        $out[$id] = trim($v);
    }
    return $out;
}

/**
 * Which response ids the back-fill looks at for this member: above $after (the owner's browser moves it past what it
 * stored or could not open) and, with only new answers, above results_since. No upper bound. Not shared_upto: that
 * only records progress, so an answer the owner's browser could not open before is offered again next time.
 * @return array{0: int, 1: int} [exclusive low, inclusive high]
 */
function backfill_window(array $member, int $after): array
{
    $floor = (int)($member['share_existing'] ?? 0) === 1 ? 0 : (int)($member['results_since'] ?? 0);
    return [max(0, $after, $floor), PHP_INT_MAX];
}

/** Responses of the survey sealed for the owner, in the window, that have no copy for the member yet. Args: user, survey, low, high. */
const BACKFILL_MISSING = 'FROM responses r LEFT JOIN response_seals rs ON rs.response_id = r.id AND rs.user_id = ?
    WHERE r.survey_id = ? AND r.sealed IS NOT NULL AND r.id > ? AND r.id <= ? AND rs.response_id IS NULL';

/**
 * Per results-collaborator with a key: the sealed responses in their window (and above $after) that still have no
 * copy for them, at most $limit at a time, with how many lack one in all.
 * @return list<array{user: int, name: string, key: int, public: string, responses: list<int>, total: int}>
 */
function backfill_todo(int $surveyId, int $after = 0, int $limit = 50): array
{
    $out = [];
    foreach (rows('SELECT m.user_id, m.results_since, m.share_existing, u.display_name FROM survey_members m JOIN users u ON u.id = m.user_id
                   WHERE m.survey_id = ? AND m.accepted_at IS NOT NULL AND m.results = 1 ORDER BY m.invited_at, m.id', [$surveyId]) as $m) {
        $key = e2e_current_key((int)$m['user_id']);
        if (!$key) continue;
        $ids = array_map('intval', array_column(rows('SELECT r.id ' . BACKFILL_MISSING . ' ORDER BY r.id LIMIT ' . max(1, $limit),
            [$m['user_id'], $surveyId, ...backfill_window($m, $after)]), 'id'));
        if (!$ids) continue;
        $out[] = ['user' => (int)$m['user_id'], 'name' => (string)$m['display_name'], 'key' => $key['id'], 'public' => $key['public'],
            'responses' => $ids, 'total' => (int)val('SELECT COUNT(*) ' . BACKFILL_MISSING, [$m['user_id'], $surveyId, ...backfill_window($m, 0)])];
    }
    return $out;
}

/** Whether the owner still has answers to share with this member (their results page says so meanwhile). */
function backfill_pending(int $surveyId, array $member): bool
{
    if ((int)$member['results'] !== 1 || $member['user_id'] === null) return false;
    return (bool)val('SELECT 1 ' . BACKFILL_MISSING . ' LIMIT 1', [$member['user_id'], $surveyId, ...backfill_window($member, 0)]);
}

/**
 * How many answers this member will not get: with only new answers shared, the sealed ones up to results_since that
 * have no copy for them (their results page says so). Every other missing copy is still to come (backfill_pending()).
 */
function backfill_not_shared(int $surveyId, array $member): int
{
    if ((int)$member['results'] !== 1 || (int)$member['share_existing'] === 1 || $member['user_id'] === null) return 0;
    return (int)val('SELECT COUNT(*) ' . BACKFILL_MISSING, [$member['user_id'], $surveyId, 0, (int)($member['results_since'] ?? 0)]);
}

/**
 * Store the owner's back-fill copies for one collaborator, checked by backfill_accepts() against the member row as it is
 * now (locked, so switching their results off cannot cross it), and raise shared_upto. Returns how many were new.
 */
function store_backfill(int $surveyId, int $userId, int $postedKey, array $copies): int
{
    if (!$copies || count($copies) > 50) return 0;
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $member = row('SELECT * FROM survey_members WHERE survey_id = ? AND user_id = ? AND accepted_at IS NOT NULL FOR UPDATE', [$surveyId, $userId]);
        $key = e2e_current_key($userId);
        $ids = array_values(array_filter(array_keys($copies), fn($id) => is_int($id) || ctype_digit((string)$id)));
        $ofSurvey = $ids ? array_column(rows('SELECT id FROM responses WHERE survey_id = ? AND sealed IS NOT NULL AND id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')',
            [$surveyId, ...array_map('intval', $ids)]), 'id') : [];
        $accepted = $member && $key && member_holds_access($member) ? backfill_accepts($copies, $member, $key['id'], $postedKey, $ofSurvey) : [];
        $n = 0;
        foreach ($accepted as $rid => $sealed) {
            $n += q('INSERT IGNORE INTO response_seals (response_id, user_id, key_id, sealed) VALUES (?, ?, ?, ?)', [$rid, $userId, $key['id'], $sealed])->rowCount();
        }
        if ($accepted) {
            q('UPDATE survey_members SET shared_upto = GREATEST(COALESCE(shared_upto, 0), ?) WHERE id = ?', [max(array_keys($accepted)), $member['id']]);
        }
        $pdo->commit();
    } catch (Throwable $ex) {
        $pdo->rollBack();
        throw $ex;
    }
    return $n;
}

/**
 * Answers to read in the browser: sealed ones as they are, older plain ones as values. For the owner ($forUser null) the
 * sealed answers themselves; for a results-collaborator their own copy, and a response without one only as counted.
 */
function survey_response_data(int $surveyId, array $questions, ?int $forUser = null): array
{
    $multi = multi_ids($questions);
    $out = [];
    $plain = [];
    foreach (rows('SELECT a.response_id, a.question_id, a.value FROM answers a JOIN responses r ON r.id = a.response_id WHERE r.survey_id = ?', [$surveyId]) as $a) {
        $plain[(int)$a['response_id']][(string)$a['question_id']] = $a['value'];
    }
    $sql = $forUser === null
        ? 'SELECT id, created_at, sealed, key_id, skipped FROM responses WHERE survey_id = ? ORDER BY id DESC'
        : 'SELECT r.id, r.created_at, r.skipped, IF(r.sealed IS NULL, NULL, rs.sealed) AS sealed, rs.key_id, r.sealed IS NOT NULL AS was_sealed
           FROM responses r LEFT JOIN response_seals rs ON rs.response_id = r.id AND rs.user_id = ? WHERE r.survey_id = ? ORDER BY r.id DESC';
    foreach (rows($sql, $forUser === null ? [$surveyId] : [$forUser, $surveyId]) as $r) {
        $item = ['id' => (int)$r['id'], 'at' => (int)$r['created_at']];
        if ($forUser !== null && (int)$r['was_sealed'] === 1 && $r['sealed'] === null) {
            $item['unshared'] = true;
        } elseif ($r['sealed'] !== null) {
            $item['sealed'] = $r['sealed'];
            $item['key'] = $r['key_id'] === null ? null : (int)$r['key_id'];
        } else {
            $a = [];
            foreach ($plain[(int)$r['id']] ?? [] as $qid => $value) {
                $a[$qid] = isset($multi[(int)$qid]) ? array_values(json_decode($value, true) ?: []) : $value;
            }
            $item['answers'] = (object)$a;
            // Plain responses carry their route too, so an encrypted survey with older readable ones shows it.
            $item['skipped'] = array_keys(skipped_counts([$r['skipped']]));
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
