<?php
declare(strict_types=1);

/*
 * The owner's encryption keys (src/e2e.php). The browser makes, locks and opens them (assets/vault.js);
 * these pages store the public keys and the locked copies, and give the owner's browser the sealed
 * answers to open.
 */

/** What vault.js needs on every page of a signed-in owner: their keys, locked as they are stored. */
function keyring(array $user): array
{
    $b = row('SELECT backup_public, backup_wrapped FROM users WHERE id = ?', [$user['id']]);
    return [
        'user' => (int)$user['id'], 'salt' => user_salt($user), 'v' => (int)$user['pw_v'],
        'keys' => array_map(fn($k) => ['id' => $k['id'], 'public' => $k['public'], 'salt' => $k['salt'], 'wrap' => $k['wrap'], 'backup' => $k['backup']],
            e2e_keys((int)$user['id'])),
        'backupPublic' => $b['backup_public'] ?? null,
        'backupWrapped' => isset($b['backup_wrapped']) ? e2e_unstore($b['backup_wrapped'], (int)$user['id']) : null,
        'csrf' => csrf_token(),
    ];
}

/**
 * A new key, made in the browser: the first one, or a fresh one after a password reset, when no key
 * opens with the current password. Answered as JSON, for vault.js.
 */
function page_account_key_create(): never
{
    if (!is_post()) json_out(['error' => 'POST'], 405);
    csrf_check();
    $user = current_user();
    if (!$user) json_out(['error' => 'signed-out'], 401);
    // Sent when the browser has no unlock key from signing in (and always for an account from before):
    // then the password confirms that the key is locked with the right one.
    if (isset($_POST['current_password']) || isset($_POST['current_password_auth'])) {
        if (!password_ok($user, 'current_password')) json_out(['error' => 'password'], 403);
        $user = user_by('id', (int)$user['id']);
    }
    if ((int)$user['pw_v'] !== 1) json_out(['error' => 'password'], 403);
    $salt = user_salt($user);
    if (val('SELECT 1 FROM user_keys WHERE user_id = ? AND wrap_salt = ? LIMIT 1', [$user['id'], $salt])) json_out(['error' => 'exists'], 409);
    $public = e2e_valid_public_key(post('public', 300));
    $wrap = e2e_valid_wrapped(post('wrap', E2E_MAX_WRAPPED), 'wrap');
    $hasBackup = val('SELECT backup_public FROM users WHERE id = ?', [$user['id']]) !== null;
    $backup = $hasBackup ? e2e_valid_wrapped(post('backup', E2E_MAX_WRAPPED), 'sealed') : null;
    if (!$public || !$wrap || ($hasBackup && !$backup)) json_out(['error' => 'invalid'], 422);
    q('INSERT INTO user_keys (user_id, public_key, wrap, wrap_salt, backup, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        [$user['id'], $public, e2e_store($wrap, (int)$user['id']), $salt, $backup === null ? null : e2e_store($backup, (int)$user['id']), time()]);
    json_out(['ok' => true, 'id' => (int)db()->lastInsertId()]);
}

/**
 * Keys locked with an earlier password, opened in the browser with that password, the backup code or an
 * unlock key this device still had, and locked again with the current password. Answered as JSON.
 */
function page_account_key_restore(): never
{
    if (!is_post()) json_out(['error' => 'POST'], 405);
    csrf_check();
    $user = current_user();
    if (!$user) json_out(['error' => 'signed-out'], 401);
    $wraps = e2e_posted_list('wraps', 'wrap');
    if (!$wraps) json_out(['error' => 'invalid'], 422);
    json_out(['ok' => true, 'n' => e2e_relock((int)$user['id'], $wraps, user_salt($user))]);
}

/** A backup key, the first or a new one: it can open every key it was given here, also after a password reset. */
function page_account_backup(): never
{
    only_post('/account#back-up');
    $user = require_user();
    confirm_password($user, '/account#back-up');
    $public = e2e_valid_public_key(post('backup_public', 300));
    $wrapped = e2e_valid_wrapped(post('backup_wrapped', E2E_MAX_WRAPPED), 'code');
    $seals = e2e_posted_list('backups', 'sealed');
    $keys = array_column(rows('SELECT id FROM user_keys WHERE user_id = ?', [$user['id']]), 'id');
    if (!$public || !$wrapped || ($keys && !$seals)) {
        flash(t('De back-upsleutel kon niet worden gemaakt. Vernieuw de pagina en probeer het opnieuw.'), 'error');
        redirect('/account#back-up');
    }
    $uid = (int)$user['id'];
    db()->beginTransaction();
    q('UPDATE users SET backup_public = ?, backup_wrapped = ?, backup_since = ? WHERE id = ?', [$public, e2e_store($wrapped, $uid), time(), $uid]);
    q('UPDATE user_keys SET backup = NULL WHERE user_id = ?', [$uid]);
    foreach ($seals as $id => $sealed) q('UPDATE user_keys SET backup = ? WHERE id = ? AND user_id = ?', [e2e_store($sealed, $uid), $id, $uid]);
    db()->commit();
    flash(t('Je back-upsleutel is klaar. Bewaar hem goed: een eerdere back-upsleutel werkt niet meer.'));
    redirect('/account#back-up');
}

/** The questions and every response, sealed ones as they are, for the owner's browser to open. */
function page_survey_data(string $id): never
{
    $user = current_user();
    if (!$user) json_out(['error' => t('Je bent uitgelogd.')], 401);
    $survey = row('SELECT * FROM surveys WHERE public_id = ? AND user_id = ?', [$id, $user['id']]);
    if (!$survey) json_out(['error' => t('Deze enquête bestaat niet meer.')], 404);
    $questions = survey_questions((int)$survey['id']);
    json_out([
        'survey' => (int)$survey['id'],
        'questions' => array_map(fn($q) => ['id' => $q['id'], 'type' => $q['type'], 'title' => $q['title'],
            'choices' => $q['options']['choices'] ?? [], 'min' => (int)($q['options']['min'] ?? 1), 'max' => (int)($q['options']['max'] ?? 10)], $questions),
        'responses' => array_map(fn($r) => $r + ['date' => fmt_date($r['at']), 'time' => fmt_time($r['at']), 'stamp' => date('Y-m-d H:i', $r['at'])],
            survey_response_data((int)$survey['id'], $questions)),
    ]);
}
