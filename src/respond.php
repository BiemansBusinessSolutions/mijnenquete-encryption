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

/* --- Answering ------------------------------------------------------------------------ */

function show_survey(array $survey, array $owner): never
{
    $viewer = current_user();
    $isOwner = $viewer && (int)$viewer['id'] === (int)$owner['id'];
    // A concept exists only for its maker; to everyone else the link does not exist yet.
    if ($survey['status'] === 'draft' && !$isOwner) not_found();

    $questions = survey_questions((int)$survey['id']);
    $locked = survey_password($survey) !== null;
    // A survey behind a password shows nothing of itself in a link preview.
    $encrypted = survey_encrypted($survey);
    $ownerKey = $encrypted ? e2e_current_key((int)$owner['id']) : null;
    $base = ['title' => $locked ? t('Enquête met wachtwoord') : $survey['title'], 'survey' => $survey, 'encrypted' => $encrypted,
        'description' => $locked || $survey['description'] === ''
            ? t('Een enquête van {name} op Mijn Enquête.', ['name' => $owner['display_name']]) : $survey['description'],
        'owner' => $owner, 'isOwner' => $isOwner, 'ownerEmail' => mask_email($owner['email']),
        'action' => survey_path($survey, $owner['username']), 'unlock' => null];

    if ($survey['status'] === 'closed') view('survey-closed', $base, 'survey');

    // Only the owner, or someone who typed the password, sees the questions.
    if ($locked && !$isOwner) {
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

    if (isset($_GET['verstuurd'])) view('survey-thanks', $base, 'survey');
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
                $device = claim_device_answer($survey, $isOwner);
                if (!$device['allowed']) view('survey-done', $base, 'survey');
                store_sealed_response((int)$survey['id'], trim($_POST['sealed']), $ownerKey['id']);
                note_response_activity($survey, $device, $isOwner);
                redirect($base['action'] . '?verstuurd=1' . ($base['unlock'] ? '&k=' . rawurlencode($base['unlock']) : ''));
            }
        } else {
            [$answers, $errors] = collect_answers($questions, $posted);
            if (!$errors && !$answers) $errors[0] = t('Je hebt nog niets ingevuld.');
            if (!$errors) {
                $device = claim_device_answer($survey, $isOwner);
                if (!$device['allowed']) view('survey-done', $base, 'survey');
                store_response((int)$survey['id'], $answers);
                note_response_activity($survey, $device, $isOwner);
                redirect($base['action'] . '?verstuurd=1' . ($base['unlock'] ? '&k=' . rawurlencode($base['unlock']) : ''));
            }
        }
    }
    view('survey', $base + ['questions' => $questions, 'errors' => $errors, 'posted' => $posted,
        'publicKey' => $ownerKey['public'] ?? null, 'scripts' => $encrypted ? ['e2e.js', 'survey.js'] : ['survey.js']],
        'survey', $errors ? 422 : 200);
}
