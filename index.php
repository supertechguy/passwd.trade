<?php

if (file_exists('opt/capcha.php')) {
    include 'opt/capcha.php';
}
require_once('config/config.php');

////////////////////
///SECURITY SETUP
////////////////////

if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
        'use_only_cookies' => true,
    ]);
}

const MAX_SECRET_LENGTH = 10000;
const MAX_SHARED_SECRET_LENGTH = 255;
const MIN_SHARED_SECRET_LENGTH = 12;
const MAX_ENCRYPTED_PAYLOAD_LENGTH = 30000;
const DEFAULT_TTL_SECONDS = 3600;
const CSRF_TOKEN_BYTES = 32;
const RATE_LIMIT_WINDOW_SECONDS = 900;
const CREATE_RATE_LIMIT_MAX = 20;
const DECRYPT_RATE_LIMIT_MAX = 40;
const PASSWORD_ATTEMPT_LIMIT_MAX = 12;
const PBKDF2_ITERATIONS = 250000;


set_security_headers();

////////////////////
///DB CONNECTION
////////////////////

$mysqli = new mysqli($mysql_host, $mysql_user, $mysql_passwd, $mysql_db);

if ($mysqli->connect_errno) {
    error_log('Failed to connect to MySQL: ' . $mysqli->connect_error);
    exit('Failed to connect to MySQL. Please try again later.');
}

prune_expired_records($mysqli);

function set_security_headers()
{
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function prune_expired_records($mysqli)
{
    if ($mysqli instanceof mysqli && !$mysqli->connect_errno) {
        $now = time();
        foreach (['DELETE FROM passwds WHERE expires <= ?', 'DELETE FROM rate_limits WHERE reset_at <= ?'] as $sql) {
            $stmt = $mysqli->prepare($sql);
            if ($stmt) {
                $stmt->bind_param('i', $now);
                $stmt->execute();
                $stmt->close();
            }
        }
    }
}

function log_error($message)
{
    error_log($message);
}

function client_fingerprint()
{
    return hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . '|' . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'));
}

function enforce_rate_limit($mysqli, $bucket, $maxAttempts, $windowSeconds)
{
    $clientKey = client_fingerprint() . '|' . $bucket;
    $now = time();
    $resetAt = $now + $windowSeconds;

    $mysqli->begin_transaction();

    $stmt = $mysqli->prepare('DELETE FROM rate_limits WHERE bucket=? AND reset_at<=?');
    $stmt->bind_param('si', $clientKey, $now);
    $stmt->execute();
    $stmt->close();

    $stmt = $mysqli->prepare('INSERT INTO rate_limits (bucket, count, reset_at) VALUES (?, 1, ?) ON DUPLICATE KEY UPDATE count=count+1');
    $stmt->bind_param('si', $clientKey, $resetAt);
    $stmt->execute();
    $stmt->close();

    $stmt = $mysqli->prepare('SELECT count FROM rate_limits WHERE bucket=?');
    $stmt->bind_param('s', $clientKey);
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    $mysqli->commit();

    if ($count > $maxAttempts) {
        http_response_code(429);
        exit('Too many requests. Please wait and try again.');
    }
}

function validate_ascii_keyboard_text($input, $fieldName, $maxLength, $allowNewlines = true)
{
    if (!is_string($input)) {
        log_error('Rejected invalid ' . $fieldName . ' input type');
        exit('Invalid input.');
    }

    if ($input === '') {
        exit('Missing required input.');
    }

    if (strlen($input) > $maxLength) {
        exit('Input is too large.');
    }

    $pattern = $allowNewlines ? '/^[\x20-\x7E\r\n]+$/' : '/^[\x20-\x7E]+$/';
    if (!preg_match($pattern, $input)) {
        log_error('Rejected invalid characters in ' . $fieldName);
        exit('Invalid input. Please enter only normal keyboard characters.');
    }

    return $input;
}

function clear_memory(...$vars)
{
    foreach ($vars as &$var) {
        if (!is_string($var)) {
            $var = null;
            continue;
        }

        $length = strlen($var);
        if ($length > 0) {
            $var = str_repeat("\0", $length);
        }
        $var = null;
    }
    unset($var);
}

function generate_csrf_token()
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(CSRF_TOKEN_BYTES));
    }
    return $_SESSION['csrf_token'];
}

function require_valid_csrf_token()
{
    $posted = $_POST['csrf_token'] ?? '';
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    if (!is_string($posted) || !is_string($sessionToken) || $posted === '' || !hash_equals($sessionToken, $posted)) {
        exit('Invalid request token.');
    }
}


function bot_detected()
{
    return (
        isset($_SERVER['HTTP_USER_AGENT'])
        && preg_match('/bot|crawl|slurp|spider|mediapartners/i', $_SERVER['HTTP_USER_AGENT'])
    );
}

function base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data)
{
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

function generate_key_1()
{
    return base64url_encode(random_bytes(32));
}

function generate_key_2()
{
    return base64url_encode(random_bytes(64));
}

function generate_code()
{
    return base64url_encode(random_bytes(32));
}

function secured_encrypt($data, $key1, $key2)
{
    $first_key = base64url_decode($key1);
    $second_key = base64url_decode($key2);

    $method = 'aes-256-cbc';
    $iv_length = openssl_cipher_iv_length($method);
    $iv = random_bytes($iv_length);

    $first_encrypted = openssl_encrypt($data, $method, $first_key, OPENSSL_RAW_DATA, $iv);
    $mac = hash_hmac('sha3-512', $iv . $first_encrypted, $second_key, true);

    return base64url_encode($iv . $mac . $first_encrypted);
}

function secured_decrypt($input, $key1, $key2)
{
    $first_key = base64url_decode($key1);
    $second_key = base64url_decode($key2);
    $mix = base64url_decode($input);

    $method = 'aes-256-cbc';
    $iv_length = openssl_cipher_iv_length($method);

    $iv = substr($mix, 0, $iv_length);
    $mac = substr($mix, $iv_length, 64);
    $first_encrypted = substr($mix, $iv_length + 64);

    $mac_new = hash_hmac('sha3-512', $iv . $first_encrypted, $second_key, true);

    if (!hash_equals($mac, $mac_new)) {
        return false;
    }

    $data = openssl_decrypt($first_encrypted, $method, $first_key, OPENSSL_RAW_DATA, $iv);
    return $data !== false ? $data : false;
}

function html_escape($value)
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function display_headers($project_title)
{
    $safe_title = html_escape($project_title);
    $iterations = PBKDF2_ITERATIONS;
    $minPassword = MIN_SHARED_SECRET_LENGTH;
    $passwordAttemptLimit = PASSWORD_ATTEMPT_LIMIT_MAX;
    echo <<<HTML
<html>
<head>
<title>{$safe_title}</title>
<link rel="stylesheet" href="/app.css">
</head>
<body data-pbkdf2-iterations="{$iterations}" data-min-secret-length="{$minPassword}" data-attempt-limit="{$passwordAttemptLimit}">
<center>
<br>
<img src='/supertechguy-avatar-redeagle.svg' width='100px'>
<br>
HTML;
}

function display_footers()
{
    echo <<<HTML
<script src="/app.js"></script>
</body>
</html>
HTML;
}

function display_form()
{
    $csrfToken = html_escape(generate_csrf_token());
    echo <<<HTML
<br>
<h1>Enter password to encrypt and send</h1>
<form method='POST' action='/index.php?action=encrypt' id='encrypt-form' autocomplete='off'>
  <textarea id='plaintext' rows='5' cols='60' maxlength='10000' autofocus></textarea><br><br>
  <p class="helptext">Shared secret (for client side encryption)<br>must be communicated to recipient out-of-band</p>
  <input id='SHARED_SECRET' rows='1' type='text' maxlength='255' size='60' autocomplete='off' placeholder='Shared secret'><br><br>
  <select name='ttl' id='ttl'>
    <option value='900'>Expire in 15 minutes</option>
    <option value='3600' selected>Expire in 1 hour</option>
    <option value='86400'>Expire in 24 hours</option>
  </select><br><br>
  <input type='hidden' id='encrypted_payload' name='encrypted_payload' value=''>
  <input type='hidden' name='csrf_token' value='{$csrfToken}'>
  <div id='encrypt-status' class='status'></div><br>
  <input class='button' type='submit' value='Generate Link'>
</form>
HTML;
}

function display_link($link)
{
    $safe_link = html_escape($link);
    echo <<<HTML
<br>
<h1>Send this link to the recipient</h1>
<p class="helptext">The recipient will also need the shared secret you gave them separately.</p>
<textarea id='link' name='link' rows='5' cols='60' autofocus>{$safe_link}</textarea>
<div class='tooltip'>
<button class='button' id='copy-link-btn'>
  <span class='tooltiptext' id='linkTooltip' data-default-text='Copy to clipboard'>Copy to clipboard</span>
  Copy Link
</button>
</div>
<input class='button reset-btn' type='button' value='Reset' />
HTML;
}

function display_decrypt_form($client_encrypted_payload)
{
    $safe_payload = html_escape($client_encrypted_payload);
    echo <<<HTML
<br>
<h1>Encrypted text retrieved</h1>
<p class="helptext">The server copy has been destroyed. Enter the shared password you received separately, then click Decrypt. Decryption happens in your browser.</p>
<textarea id='client_encrypted_payload' rows='8' cols='60' class='hidden'>{$safe_payload}</textarea><br>
<input id='decrypt_SHARED_SECRET' type='password' maxlength='255' size='60' autocomplete='off' placeholder='Shared password'><br><br>
<input class='button' type='button' id='decrypt-button' value='Decrypt' />
<div id='decrypt-status' class='status'><br></div>
<div id='decrypted_text_section' class='hidden'>
  <h1>Your text is:</h1>
  <textarea id='decrypted_text' name='decrypted_text' rows='5' cols='60' autofocus readonly></textarea><br><br>
  <p>This page will only be accessible once. You must copy the text now.</p>
  <p class='text-red'>[Data Destroyed]</p>
  <div class='tooltip'>
    <button class='button' id='copy-text-btn'>
      <span class='tooltiptext' id='secretTooltip' data-default-text='Copy to clipboard'>Copy to clipboard</span>
      Copy Text
    </button>
  </div>
  <input class='button reset-btn' type='button' value='Reset' />
</div>
HTML;
}

function display_error($message = '[ERROR]')
{
    $safeMessage = html_escape($message);
    echo <<<HTML
<br>
  <p class='text-red'>{$safeMessage}</p>
  <input class='button reset-btn' type='button' value='Reset' />
HTML;
}

////////////////////
///ENV VARS
////////////////////

$action = isset($_GET['action']) ? $_GET['action'] : '';

/////////////////////
///MAIN RUNTIME CODE
/////////////////////

if (bot_detected()) {
    $safe_title = html_escape($project_title);
    echo "
<html>
<head>
<title>{$safe_title}</title>
<body>
<h1>{$safe_title}</h1>
</body>
</html>
";
} else {
    display_headers($project_title);
    switch ($action) {
        case 'encrypt':
            enforce_rate_limit($mysqli, 'create', CREATE_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS);
            require_valid_csrf_token();

            $ttl = (int)($_POST['ttl'] ?? DEFAULT_TTL_SECONDS);
            $allowedTtls = [900, 3600, 86400];
            if (!in_array($ttl, $allowedTtls, true)) {
                $ttl = DEFAULT_TTL_SECONDS;
            }

            $ts = time();
            $expires = $ts + $ttl;
            $host = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown');

            $encrypted_payload = validate_ascii_keyboard_text($_POST['encrypted_payload'] ?? '', 'encrypted payload', MAX_ENCRYPTED_PAYLOAD_LENGTH, false);

            $payloadData = json_decode($encrypted_payload, true);
            if (!is_array($payloadData)) {
                display_error('Invalid encrypted payload.');
                break;
            }

            $requiredPayloadKeys = ['v', 'alg', 'kdf', 'iter', 'salt', 'iv', 'ct'];
            foreach ($requiredPayloadKeys as $payloadKey) {
                if (!array_key_exists($payloadKey, $payloadData)) {
                    display_error('Invalid encrypted payload.');
                    break 2;
                }
            }

            if (
                (int)$payloadData['v'] !== 1
                || $payloadData['alg'] !== 'AES-GCM'
                || $payloadData['kdf'] !== 'PBKDF2-SHA-256'
                || (int)$payloadData['iter'] !== PBKDF2_ITERATIONS
            ) {
                display_error('Unsupported encrypted payload settings.');
                break;
            }

            $key1 = generate_key_1();
            $key2 = generate_key_2();
            $code = generate_code();
            $encrypted_passwd = secured_encrypt($encrypted_payload, $key1, $key2);

            $stmt = $mysqli->prepare('INSERT INTO passwds (code, passwd, host, ts, expires) VALUES (?, ?, ?, ?, ?)');
            $stmt->bind_param('sssii', $code, $encrypted_passwd, $host, $ts, $expires);
            $stmt->execute();
            $stmt->close();

            $link = "$project_url/d/$code/$key1/$key2/";
            display_link($link);

            clear_memory($encrypted_payload, $key1, $key2, $code, $encrypted_passwd);
            break;

        case 'decrypt':
            enforce_rate_limit($mysqli, 'retrieve', DECRYPT_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS);

            $key1 = validate_ascii_keyboard_text($_GET['key1'] ?? '', 'key1', 128, false);
            $key2 = validate_ascii_keyboard_text($_GET['key2'] ?? '', 'key2', 128, false);
            $code = validate_ascii_keyboard_text($_GET['code'] ?? '', 'code', 128, false);

            $now = time();
            $mysqli->begin_transaction();

            $stmt = $mysqli->prepare('SELECT passwd FROM passwds WHERE code=? AND expires>? FOR UPDATE');
            $stmt->bind_param('si', $code, $now);
            $stmt->execute();
            $stmt->bind_result($encrypted_passwd);
            $stmt->fetch();
            $stmt->close();

            if ($encrypted_passwd) {
                $stmt = $mysqli->prepare('DELETE FROM passwds WHERE code=?');
                $stmt->bind_param('s', $code);
                $stmt->execute();
                $stmt->close();
                $mysqli->commit();

                $client_encrypted_payload = secured_decrypt($encrypted_passwd, $key1, $key2);
                if ($client_encrypted_payload !== false) {
                    display_decrypt_form($client_encrypted_payload);
                } else {
                    display_error();
                }
            } else {
                $mysqli->rollback();
                display_error('This link is invalid, expired, or already used.');
            }

            clear_memory($key1, $key2, $code, $encrypted_passwd, $client_encrypted_payload ?? null);
            break;

        default:
            display_form();
    }

    display_footers();
}

$mysqli->close();
?>
