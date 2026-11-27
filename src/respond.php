<?php
declare(strict_types=1);

/*
 * Everything a respondent's visit touches, in one file, so it can be read in full: the published
 * encryption source (github.com/BiemansBusinessSolutions/mijnenquete-encryption) includes it.
 *
 * What is kept about a respondent, and for how long:
 *  - The IP address is never stored. It is only counted against floods, as a keyed hash (ip_key) in
 *    rate_limits, and that row is gone when its window ends (at most an hour for answering).
 *  - After answering, the browser gets one cookie with a random code (no tracking). The server keeps a
 *    keyed hash of it per survey, without a time, only to say "you have already filled this in".
 *    Accounts keep their own, differently keyed hash of the devices they sign in on, with only the
 *    day. Neither can be matched to the other, nor to an answer, without the cookie itself.
 *  - The answer itself: sealed in the browser for an encrypted survey (src/e2e.php), with the time it
 *    arrived. No device, address or account is stored with it.
 *  - A survey behind a password carries an unlock token in the form (k). It names the survey and a
 *    time, not a person: everyone who opens it in the same second gets the same token.
 *  - A survey for allowed email addresses only: the address a respondent types is checked against the
 *    owner's list and then only kept as a keyed hash, different per survey: for 15 minutes (14 days for
 *    an invitation) next to the code, and, once it has answered, permanently without a time, only to say
 *    "you have already filled this in". So Mijn Enquête can tell which allowed addresses answered, but not
 *    which answer is whose; the owner sees neither. The code goes out through Brevo (France), which gets
 *    the address and the code to deliver the mail.
 *
 * Not in this file: what the web server and Cloudflare log about requests. See PROTOCOL.md.
 */

/** How long one correct password keeps the form open (the respondent's unlock token). */
const UNLOCK_TTL = 12 * 3600;
const DEVICE_COOKIE_LIFETIME = 400 * 86400; // the longest browsers keep a cookie

/* --- Addresses: counted, never stored ------------------------------------------ */

/** Cloudflare's published ranges (cloudflare.com/ips). Only a request from these may name the visitor. */
const CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

function ip_in_range(string $ip, string $cidr): bool
{
    [$net, $bits] = explode('/', $cidr);
    $a = @inet_pton($ip);
    $b = @inet_pton($net);
    if ($a === false || $b === false || strlen($a) !== strlen($b)) return false;
    $bits = (int)$bits;
    $bytes = intdiv($bits, 8);
    if (substr($a, 0, $bytes) !== substr($b, 0, $bytes)) return false;
    if ($bits % 8 === 0) return true;
    $mask = 0xff << (8 - $bits % 8) & 0xff;
    return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
}

function is_public_ip(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

/**
 * The visitor's address, for rate limits. Each hop is only believed when the hop before it is
 * one we trust:
 *  1. A proxy inside the hosting network (a private REMOTE_ADDR) appends the address it saw as
 *     the last X-Forwarded-For entry; earlier entries are whatever the client sent.
 *  2. If that address is Cloudflare's, Cloudflare names the visitor in CF-Connecting-IP.
 * Anyone else who sends those headers is ignored and counted by their own address.
 */
function client_ip(): string
{
    $peer = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    if (!is_public_ip($peer)) {
        $chain = array_map('trim', explode(',', (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '')));
        $last = (string)end($chain);
        if (is_public_ip($last)) $peer = $last;
    }
    $visitor = trim((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
    if ($visitor !== '' && filter_var($visitor, FILTER_VALIDATE_IP)) {
        foreach (CLOUDFLARE_RANGES as $range) {
            if (ip_in_range($peer, $range)) return $visitor;
        }
    }
    return $peer;
}

/**
 * Count one attempt against $key; false once more than $max happened within $seconds.
 * Lives in the database because PHP keeps nothing in memory between requests.
 */
function rate_ok(string $key, int $max, int $seconds): bool
{
    $now = time();
    $k = substr($key, 0, 120);
    if (random_int(1, 200) === 1) q('DELETE FROM rate_limits WHERE reset_at < ?', [$now]);
    q('INSERT INTO rate_limits (k, hits, reset_at) VALUES (?, 1, ?)
       ON DUPLICATE KEY UPDATE hits = IF(reset_at < ?, 1, hits + 1), reset_at = IF(reset_at < ?, ?, reset_at)',
        [$k, $now + $seconds, $now, $now, $now + $seconds]);
    return (int)val('SELECT hits FROM rate_limits WHERE k = ?', [$k]) <= $max;
}

/** Rate-limit keys never hold a raw address: a keyed hash is enough to count with. */
function ip_key(string $scope): string
{
    return $scope . ':' . substr(hash_hmac('sha256', client_ip(), app_key('ip')), 0, 32);
}

/* --- Devices: "you already answered" ------------------------------------------- */

function device_cookie_name(): string
{
    return is_https() ? '__Host-me_device' : 'me_device';
}

/** This browser's device code, when it has one. */
function device_code(): ?string
{
    $code = $_COOKIE[device_cookie_name()] ?? '';
    return is_string($code) && preg_match('/^[a-f0-9]{32}$/', $code) ? $code : null;
}

/** The device code, made now if there is none yet. Only called after the visitor acts: answering, signing in. */
function ensure_device_code(): string
{
    $code = device_code();
    if ($code !== null) return $code;
    $code = bin2hex(random_bytes(16));
    if (!headers_sent()) {
        setcookie(device_cookie_name(), $code, [
            'expires' => time() + DEVICE_COOKIE_LIFETIME, 'path' => '/', 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax',
        ]);
    }
    $_COOKIE[device_cookie_name()] = $code;
    return $code;
}

/**
 * Keyed, and different for every place it is kept ('survey:<id>' or 'user:<id>'), so stored values
 * can be matched neither to a cookie nor to each other without the cookie itself.
 */
function device_hash(string $code, string $scope): string
{
    return substr(hash_hmac('sha256', $scope . '|' . $code, app_key('device')), 0, 32);
}

/**
 * The value used for every survey before 2026-11-19, kept only to recognise devices that answered then.
 * ponytail: remove after 2027-12-24, when every cookie from before has expired (DEVICE_COOKIE_LIFETIME).
 */
function legacy_device_hash(string $code): string
{
    return substr(hash_hmac('sha256', $code, app_key('device')), 0, 32);
}

/**
 * Remember the devices an account uses (on every signed-in request; one cheap upsert). Only the day is
 * kept: it is used to forget devices after DEVICE_COOKIE_LIFETIME, and an exact time would line up
 * with the time an answer arrived.
 */
function note_owner_device(int $userId): void
{
    q('INSERT INTO user_devices (user_id, device_hash, last_seen) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen)',
        [$userId, device_hash(ensure_device_code(), 'user:' . $userId), intdiv(time(), 86400) * 86400]);
}

/** Has this browser already answered this survey? */
function device_answered(array $survey): bool
{
    $code = device_code();
    return $code !== null && (bool)val('SELECT 1 FROM survey_devices WHERE survey_id = ? AND device_hash IN (?, ?)',
        [$survey['id'], device_hash($code, 'survey:' . $survey['id']), legacy_device_hash($code)]);
}

/**
 * Record that this device answers the survey. Returns false when it already had, and the survey
 * allows one answer per device (the owner may always answer, to test). No time is stored with it,
 * so the row cannot be lined up with the answer it belongs to.
 */
function claim_device_answer(array $survey, bool $isOwner): array
{
    $code = ensure_device_code();
    $isNew = q('INSERT IGNORE INTO survey_devices (survey_id, device_hash) VALUES (?, ?)',
            [$survey['id'], device_hash($code, 'survey:' . $survey['id'])])->rowCount() === 1
        && !val('SELECT 1 FROM survey_devices WHERE survey_id = ? AND device_hash = ?', [$survey['id'], legacy_device_hash($code)]);
    return ['allowed' => $isNew || $isOwner || !(int)$survey['one_per_device'], 'new' => $isNew,
        'owner' => device_hash($code, 'user:' . $survey['user_id'])];
}

/** After an answer is stored: does it keep the survey alive? Not when it came from a device its owner signs in on. */
function note_response_activity(array $survey, array $device, bool $isOwner): bool
{
    if (!$device['new'] || $isOwner) return false;
    if (val('SELECT 1 FROM user_devices WHERE user_id = ? AND device_hash = ?', [$survey['user_id'], $device['owner']])) return false;
    q('UPDATE surveys SET last_activity_at = ? WHERE id = ?', [time(), $survey['id']]);
    return true;
}

/* --- A survey behind a password -------------------------------------------------- */

/**
 * Proof that someone typed the right password, carried in the form as a hidden field: respondents get
 * no session and no cookie before they answer. It names the survey, its current password and a time,
 * so it stops working after UNLOCK_TTL or once the owner changes the password.
 */
function unlock_token(array $survey, ?int $at = null): string
{
    $at ??= time();
    $mac = hash_hmac('sha256', $survey['id'] . '|' . $survey['access_password'] . '|' . $at, app_key('unlock'));
    return $at . '.' . substr($mac, 0, 32);
}

function unlock_token_ok(array $survey, string $token): bool
{
    if (!preg_match('/^(\d{1,12})\.[a-f0-9]{32}$/', $token, $m)) return false;
    $at = (int)$m[1];
    if ($at > time() + 60 || $at < time() - UNLOCK_TTL) return false;
    return hash_equals(unlock_token($survey, $at), $token);
}

/* --- A survey for allowed addresses only ------------------------------------------ */

/** One address however it is typed: no spaces around it, lower case. */
function email_normal(string $email): string
{
    return strtolower(trim($email));
}

/**
 * How an address is kept: a keyed hash, different for every survey, so the same person cannot be
 * followed from one survey to another and the address cannot be read back.
 */
function email_hash(int $surveyId, string $email): string
{
    return substr(hash_hmac('sha256', $surveyId . '|' . email_normal($email), app_key('email')), 0, 32);
}

/** Is the address on the list, or its domain (written as @domain)? Subdomains do not count. */
function email_allowed_in(array $allowed, string $email): bool
{
    $email = email_normal($email);
    $at = strrpos($email, '@');
    if ($at === false || $at === 0) return false;
    return in_array($email, $allowed, true) || in_array(substr($email, $at), $allowed, true);
}

function email_access_on(array $survey): bool
{
    return (int)($survey['email_access'] ?? 0) === 1;
}

/** A requested code works 15 minutes; one in an invitation 14 days. Five tries per code. */
const CODE_TTL = 900;
const INVITE_CODE_TTL = 14 * 86400;
const CODE_ATTEMPTS = 5;

function code_hash(int $surveyId, string $emailHash, string $code): string
{
    return hash_hmac('sha256', "$surveyId|$emailHash|$code", app_key('code'));
}

/** A new 6-digit code. It is only stored (save_survey_code) once the mail with it was accepted. */
function new_survey_code(): string
{
    return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

/**
 * At most three requested codes per address per hour. The count is kept in the code's own row, which is
 * deleted when the code is used, so nothing with the address's hash and a time outlives the answer.
 * Returns the new row's count and window, or null when the limit is reached.
 */
function code_window(?array $row, int $now): ?array
{
    if ($row === null || (int)$row['window_end'] <= $now) return ['sends' => 1, 'window_end' => $now + 3600];
    if ((int)$row['sends'] >= 3) return null;
    return ['sends' => (int)$row['sends'] + 1, 'window_end' => (int)$row['window_end']];
}

function survey_code_row(int $surveyId, string $emailHash): ?array
{
    return row('SELECT sends, window_end FROM survey_codes WHERE survey_id = ? AND email_hash = ?', [$surveyId, $emailHash]);
}

/** Store the address's code; it replaces the one before. */
function save_survey_code(int $surveyId, string $emailHash, string $code, int $ttl, array $window): void
{
    q('REPLACE INTO survey_codes (survey_id, email_hash, code_hash, expires_at, attempts, sends, window_end) VALUES (?, ?, ?, ?, 0, ?, ?)',
        [$surveyId, $emailHash, code_hash($surveyId, $emailHash, $code), time() + $ttl, $window['sends'], $window['window_end']]);
}

/** Is this the address's code? A right code is used up; every try counts, right or wrong. */
function check_survey_code(int $surveyId, string $emailHash, string $code): bool
{
    q('UPDATE survey_codes SET attempts = LEAST(attempts + 1, 255) WHERE survey_id = ? AND email_hash = ?', [$surveyId, $emailHash]);
    $row = row('SELECT code_hash, expires_at, attempts FROM survey_codes WHERE survey_id = ? AND email_hash = ?', [$surveyId, $emailHash]);
    if (!$row || (int)$row['attempts'] > CODE_ATTEMPTS || (int)$row['expires_at'] < time()) return false;
    if (!hash_equals($row['code_hash'], code_hash($surveyId, $emailHash, preg_replace('/\D/', '', $code)))) return false;
    q('DELETE FROM survey_codes WHERE survey_id = ? AND email_hash = ?', [$surveyId, $emailHash]);
    return true;
}

/**
 * Like unlock_token, for someone who typed the code from their mail. It names the address's hash, so
 * the answer can be counted against that address once; it is never stored with the answer.
 */
function email_token(array $survey, string $emailHash, ?int $at = null): string
{
    $at ??= time();
    return "$at.$emailHash." . substr(hash_hmac('sha256', $survey['id'] . "|$emailHash|$at", app_key('unlock-email')), 0, 32);
}

/** The address's hash, when the token is valid. */
function email_token_hash(array $survey, string $token): ?string
{
    if (!preg_match('/^(\d{1,12})\.([a-f0-9]{32})\.[a-f0-9]{32}$/', $token, $m)) return null;
    $at = (int)$m[1];
    if ($at > time() + 60 || $at < time() - UNLOCK_TTL) return null;
    return hash_equals(email_token($survey, $m[2], $at), $token) ? $m[2] : null;
}

/** The code a respondent asked for, through Brevo, in the language they see the site in. */
function mail_respondent_code(array $survey, array $owner, string $email, string $code): bool
{
    $heading = t('Je code voor “{title}”', ['title' => $survey['title']]);
    $intro = t('Vul deze code in om de enquête van {name} te openen.', ['name' => $owner['display_name']]);
    $outro = t('De code is 15 minuten geldig. Heb je dit niet aangevraagd? Dan hoef je niets te doen.');
    $box = '<div style="font-size:32px;font-weight:bold;letter-spacing:4px;background:#ffd23f;padding:14px 18px;display:inline-block">{{ params.code }}</div>';
    return send_survey_mail(brevo_payload(brevo_sender('code'), null, t('{code} is je code voor Mijn Enquête', ['code' => '{{ params.code }}']),
        "$heading\n\n$intro\n\n{{ params.code }}\n\n$outro\n", mail_html($heading, $intro, $box, $outro),
        [['to' => email_normal($email), 'params' => ['code' => $code]]]));
}

/**
 * What the gate does with an address: 'request' (send me a code), 'have_code' (I have one from an
 * invitation) or 'code' (here it is). An address that is not, or no longer, on the list gets nothing.
 * An address that already answered gets the same "check your mail" page as any other, but no mail: the
 * gate must not tell anyone, the owner included, which addresses have answered.
 */
function email_gate_step(string $kind, bool $allowed, bool $answered): string
{
    if (!$allowed) return 'refused';
    if ($kind === 'code') return 'check';
    return $kind === 'request' && !$answered ? 'send' : 'show-code';
}

/**
 * What the gate page gets. The defaults come last: with +, the first array that has a key wins, so
 * defaults in front would drop the typed address, and the code form would post it back empty.
 */
function email_gate_vars(array $base, string $state, array $more = []): array
{
    return ['state' => $state] + $more + $base + ['email' => '', 'error' => null];
}

/**
 * The gate in front of a survey for allowed addresses only. Returns the unlock token once the visitor
 * typed a right code; otherwise shows the page for the step they are at, and does not return.
 */
function email_gate(array $survey, array $owner, array $base): string
{
    $id = (int)$survey['id'];
    $view = fn(string $state, array $more = [], int $status = 200) =>
        view('survey-email', email_gate_vars($base, $state, $more), 'survey', $status);
    // Mail costs money: only a premium survey sends codes. Without that it stays shut, never open to all.
    if (!premium_active($survey, $owner)) $view('unavailable');

    $token = $_POST['k'] ?? $_GET['k'] ?? '';
    if (is_string($token) && email_token_hash($survey, $token) !== null) return $token;
    if (!is_post()) $view('ask');

    $email = email_normal(post('email', 190));
    if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $view('ask', ['error' => t('Vul een geldig e-mailadres in, zoals naam@voorbeeld.nl.'), 'email' => $email], 422);
    }
    $kind = isset($_POST['code']) ? 'code' : (isset($_POST['have_code']) ? 'have_code' : 'request');
    // Counted before anything is looked up, so the list cannot be tried address by address.
    if ($kind === 'code' && !rate_ok(ip_key('code-check:' . $id), 30, 900)) {
        $view('code', ['email' => $email, 'error' => t('Er is te vaak een verkeerde code geprobeerd. Probeer het later opnieuw.')], 429);
    }
    if ($kind !== 'code' && !rate_ok(ip_key('code:' . $id), 20, 900)) {
        $view('ask', ['email' => $email, 'error' => t('Er zijn te veel codes aangevraagd. Probeer het later opnieuw.')], 429);
    }
    $hash = email_hash($id, $email);
    $answered = $kind === 'request'
        && (bool)val('SELECT 1 FROM survey_answered_emails WHERE survey_id = ? AND email_hash = ?', [$id, $hash]);

    switch (email_gate_step($kind, email_allowed_in(allowlist_of($id), $email), $answered)) {
        case 'refused':
            $view('refused', ['email' => $email], 403);
        case 'show-code':
            $view('code', ['email' => $email]);
        case 'check':
            if (!check_survey_code($id, $hash, post('code', 20))) {
                $view('code', ['email' => $email, 'error' => t('Deze code klopt niet of is verlopen. Vraag een nieuwe code aan.')], 422);
            }
            $_POST = []; // the code form is not an answer
            return email_token($survey, $hash);
    }
    // 'send'
    $window = code_window(survey_code_row($id, $hash), time());
    if ($window === null) $view('ask', ['email' => $email, 'error' => t('Er zijn te veel codes aangevraagd. Probeer het later opnieuw.')], 429);
    if (mail_used((int)$owner['id'], 'codes') >= CODES_PER_DAY) $view('full', ['email' => $email], 429);
    $code = new_survey_code();
    if (!mail_respondent_code($survey, $owner, $email, $code)) {
        $view('ask', ['email' => $email, 'error' => t('De code kon nu niet worden verstuurd. Probeer het later opnieuw.')], 503);
    }
    save_survey_code($id, $hash, $code, CODE_TTL, $window);
    mail_count((int)$owner['id'], 'codes', 1);
    $view('code', ['email' => $email]);
}

/**
 * Count the answer against the address, once. False when it had already answered. Called before the
 * answer is stored; release_email_answer() undoes it when the answer is refused after all.
 */
function claim_email_answer(array $survey, string $emailHash): bool
{
    return q('INSERT IGNORE INTO survey_answered_emails (survey_id, email_hash) VALUES (?, ?)', [$survey['id'], $emailHash])->rowCount() === 1;
}

function release_email_answer(array $survey, string $emailHash): void
{
    q('DELETE FROM survey_answered_emails WHERE survey_id = ? AND email_hash = ?', [$survey['id'], $emailHash]);
}

/** Store the answer; when that fails, the address may answer again ($release), so nobody is locked out. */
function store_with_claim(callable $store, callable $release): void
{
    try {
        $store();
    } catch (Throwable $ex) {
        $release();
        throw $ex;
    }
}

/**
 * Where to go after an answer. With an email token, nowhere: the token names the address's hash, and a
 * URL ends up in request logs and browser history with a time. The thanks page is shown right away.
 */
function after_answer_url(string $action, ?string $unlock, bool $byEmail): ?string
{
    if ($byEmail) return null;
    return $action . '?verstuurd=1' . ($unlock ? '&k=' . rawurlencode($unlock) : '');
}

/** The page title before the survey opens: it shows in tabs and link previews. */
function gate_title(bool $password, bool $email): string
{
    return $email ? t('Enquête voor genodigden') : t('Enquête met wachtwoord');
}

/* --- Answering ------------------------------------------------------------------------ */

function show_survey(array $survey, array $owner): never
{
    $viewer = current_user();
    $isOwner = $viewer && (int)$viewer['id'] === (int)$owner['id'];
    // A draft exists only for its maker and their collaborators (the builder's preview); to everyone else the link
    // does not exist yet. Only $isOwner bypasses the password, device and activity rules below.
    if ($survey['status'] === 'draft' && !$isOwner
        && !draft_viewable($survey, $viewer ? (int)$viewer['id'] : null, $viewer ? survey_member((int)$survey['id'], (int)$viewer['id']) : null)) not_found();

    $questions = survey_questions((int)$survey['id']);
    $byEmail = email_access_on($survey);
    $locked = survey_password($survey) !== null || $byEmail;
    // A survey behind a password shows nothing of itself in a link preview.
    $encrypted = survey_encrypted($survey);
    $ownerKey = $encrypted ? e2e_current_key((int)$owner['id']) : null;
    // Results-collaborators get their own sealed copy of each new answer (only when there is an owner key to seal for).
    $readerKeys = $ownerKey !== null ? reader_keys((int)$survey['id']) : [];
    $base = ['title' => $locked ? gate_title(survey_password($survey) !== null, $byEmail) : $survey['title'], 'survey' => $survey, 'encrypted' => $encrypted,
        'description' => $locked || $survey['description'] === ''
            ? t('Een enquête van {name} op Mijn Enquête.', ['name' => $owner['display_name']]) : $survey['description'],
        'owner' => $owner, 'isOwner' => $isOwner, 'ownerEmail' => mask_email($owner['email']),
        'readers' => readers_sentence((string)$owner['display_name'], array_column(survey_readers((int)$survey['id']), 'name'), $encrypted),
        'action' => survey_path($survey, $owner['username']), 'unlock' => null];

    if ($survey['status'] === 'closed') view('survey-closed', $base, 'survey');
    // Premium features without a subscription: no answers (GET and POST), until the owner fixes it.
    if (premium_restricted($survey, $owner, $questions)) view('survey-closed', $base + ['restricted' => true], 'survey');

    // Only the owner, or someone who typed the password, sees the questions.
    if (survey_password($survey) !== null && !$isOwner) {
        $token = $_POST['k'] ?? $_GET['k'] ?? '';
        $token = is_string($token) ? $token : '';
        $error = null;
        if (!unlock_token_ok($survey, $token) && is_post() && isset($_POST['wachtwoord'])) {
            if (!rate_ok(ip_key('unlock:' . $survey['id']), 30, 900)) {
                $error = t('Er is te vaak een verkeerd wachtwoord geprobeerd. Probeer het later opnieuw.');
            } elseif (hash_equals((string)survey_password($survey), post('wachtwoord', MAX_PASSWORD))) {
                $token = unlock_token($survey);
                $_POST = []; // the password form is not an answer
            } else {
                $error = t('Dit wachtwoord klopt niet. Vraag het na bij wie je de link stuurde.');
            }
        }
        if (!unlock_token_ok($survey, $token)) view('survey-locked', $base + ['error' => $error], 'survey', $error ? 422 : 200);
        $base['unlock'] = $token;
        $base['title'] = $survey['title'];
    }

    // Only the owner, or someone who typed the code from their mail, sees the questions.
    $emailHash = null;
    if ($byEmail && !$isOwner) {
        $base['unlock'] = email_gate($survey, $owner, $base);
        $base['title'] = $survey['title'];
        $emailHash = email_token_hash($survey, $base['unlock']);
    }

    if (isset($_GET['verstuurd'])) view('survey-thanks', $base, 'survey');
    if ($emailHash !== null && val('SELECT 1 FROM survey_answered_emails WHERE survey_id = ? AND email_hash = ?', [$survey['id'], $emailHash])) {
        view('survey-done', $base + ['byEmail' => true], 'survey');
    }
    // One answer per device, unless the owner allows more (the owner may always test).
    $onePerDevice = (int)$survey['one_per_device'] === 1 && !$isOwner;
    if ($onePerDevice && device_answered($survey)) view('survey-done', $base, 'survey');

    $errors = [];
    $posted = [];
    if (is_post() && $_POST) {
        $posted = !$encrypted && is_array($_POST['q'] ?? null) ? $_POST['q'] : [];
        if ($survey['status'] !== 'published') {
            $errors[0] = t('Dit is een voorbeeld. Publiceer de enquête om antwoorden te kunnen ontvangen.');
        } elseif (post('website') !== '') {
            view('survey-thanks', $base, 'survey'); // filled in by a script, not a person
        } elseif (!rate_ok(ip_key('answer:' . $survey['id']), 600, 3600)) {
            // A whole office shares one address, so this only stops floods, not colleagues.
            $errors[0] = t('Je antwoorden konden nu niet worden verstuurd. Probeer het later opnieuw.');
        } elseif ($encrypted) {
            if ($problem = encrypted_submission_problem($_POST, $ownerKey)) {
                $errors[0] = $problem;
            } else {
                if ($emailHash !== null && !claim_email_answer($survey, $emailHash)) view('survey-done', $base + ['byEmail' => true], 'survey');
                $device = claim_device_answer($survey, $isOwner);
                if (!$device['allowed']) {
                    if ($emailHash !== null) release_email_answer($survey, $emailHash);
                    view('survey-done', $base, 'survey');
                }
                $copies = accept_reader_seals($_POST['sealed_for'] ?? null, $_POST['readers_fp'] ?? null, $readerKeys, (int)$survey['id']);
                store_with_claim(fn() => store_sealed_response((int)$survey['id'], trim($_POST['sealed']), $ownerKey['id'], $copies),
                    function () use ($survey, $emailHash) { if ($emailHash !== null) release_email_answer($survey, $emailHash); });
                note_response_activity($survey, $device, $isOwner);
                $next = after_answer_url($base['action'], $base['unlock'], $emailHash !== null);
                if ($next === null) view('survey-thanks', $base, 'survey');
                redirect($next);
            }
        } else {
            [$answers, $errors, $skipped] = collect_answers($questions, $posted);
            if (!$errors && !$answers) $errors[0] = t('Je hebt nog niets ingevuld.');
            if (!$errors) {
                if ($emailHash !== null && !claim_email_answer($survey, $emailHash)) view('survey-done', $base + ['byEmail' => true], 'survey');
                $device = claim_device_answer($survey, $isOwner);
                if (!$device['allowed']) {
                    if ($emailHash !== null) release_email_answer($survey, $emailHash);
                    view('survey-done', $base, 'survey');
                }
                store_with_claim(fn() => store_response((int)$survey['id'], $answers, $skipped),
                    function () use ($survey, $emailHash) { if ($emailHash !== null) release_email_answer($survey, $emailHash); });
                note_response_activity($survey, $device, $isOwner);
                $next = after_answer_url($base['action'], $base['unlock'], $emailHash !== null);
                if ($next === null) view('survey-thanks', $base, 'survey');
                redirect($next);
            }
        }
    }
    view('survey', $base + ['questions' => $questions, 'errors' => $errors, 'posted' => $posted,
        'publicKey' => $ownerKey['public'] ?? null, 'readerKeys' => $readerKeys, 'scripts' => $encrypted ? ['flow.js', 'survey-collect.js', 'e2e.js', 'survey.js'] : ['flow.js', 'survey-collect.js', 'survey.js']],
        'survey', $errors ? 422 : 200);
}
