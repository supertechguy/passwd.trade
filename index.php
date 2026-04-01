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
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function prune_expired_records($mysqli)
{
    if ($mysqli instanceof mysqli && !$mysqli->connect_errno) {
        $now = time();
        $stmt = $mysqli->prepare('DELETE FROM passwds WHERE expires <= ?');
        if ($stmt) {
            $stmt->bind_param('i', $now);
            $stmt->execute();
            $stmt->close();
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

function rate_limit_store_path()
{
    return sys_get_temp_dir() . '/passwd_trade_rate_limits.json';
}

function load_rate_limit_store()
{
    $path = rate_limit_store_path();
    if (!file_exists($path)) {
        return [];
    }

    $raw = @file_get_contents($path);
    if ($raw === false || $raw === '') {
        return [];
    }

    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function save_rate_limit_store($store)
{
    $path = rate_limit_store_path();
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    @file_put_contents($path, json_encode($store), LOCK_EX);
}

function enforce_rate_limit($bucket, $maxAttempts, $windowSeconds)
{
    $store = load_rate_limit_store();
    $now = time();

    foreach ($store as $key => $entry) {
        if (!isset($entry['reset']) || $entry['reset'] <= $now) {
            unset($store[$key]);
        }
    }

    $clientKey = client_fingerprint() . '|' . $bucket;
    if (!isset($store[$clientKey]) || $store[$clientKey]['reset'] <= $now) {
        $store[$clientKey] = [
            'count' => 0,
            'reset' => $now + $windowSeconds,
        ];
    }

    if ($store[$clientKey]['count'] >= $maxAttempts) {
        save_rate_limit_store($store);
        http_response_code(429);
        exit('Too many requests. Please wait and try again.');
    }

    $store[$clientKey]['count']++;
    save_rate_limit_store($store);
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

function validate_numeric_id($input)
{
    if (!is_string($input) && !is_int($input)) {
        exit('Invalid input.');
    }

    $value = (string)$input;
    if (!preg_match('/^\d+$/', $value)) {
        exit('Invalid input.');
    }

    return (int)$value;
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
    $second_encrypted = hash_hmac('sha3-512', $first_encrypted, $second_key, true);

    return base64url_encode($iv . $second_encrypted . $first_encrypted);
}

function secured_decrypt($input, $key1, $key2)
{
    $first_key = base64url_decode($key1);
    $second_key = base64url_decode($key2);
    $mix = base64url_decode($input);

    $method = 'aes-256-cbc';
    $iv_length = openssl_cipher_iv_length($method);

    $iv = substr($mix, 0, $iv_length);
    $second_encrypted = substr($mix, $iv_length, 64);
    $first_encrypted = substr($mix, $iv_length + 64);

    $data = openssl_decrypt($first_encrypted, $method, $first_key, OPENSSL_RAW_DATA, $iv);
    $second_encrypted_new = hash_hmac('sha3-512', $first_encrypted, $second_key, true);

    if ($data !== false && hash_equals($second_encrypted, $second_encrypted_new)) {
        return $data;
    }

    return false;
}

function html_escape($value)
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function display_headers($project_title)
{
    $safe_title = html_escape($project_title);
    echo <<<HTML
<html>
<head>
<title>{$safe_title}</title>
<style>
body {
color: white;
background-color: black;
font-family: system-ui;
}
.tooltip {
  position: relative;
  display: inline-block;
}

.tooltip .tooltiptext {
  visibility: hidden;
  width: 140px;
  background-color: #555;
  color: #fff;
  text-align: center;
  border-radius: 6px;
  padding: 5px;
  position: absolute;
  z-index: 1;
  bottom: 150%;
  left: 50%;
  margin-left: -75px;
  opacity: 0;
  transition: opacity 0.3s;
}

.tooltip .tooltiptext::after {
  content: '';
  position: absolute;
  top: 100%;
  left: 50%;
  margin-left: -5px;
  border-width: 5px;
  border-style: solid;
  border-color: #555 transparent transparent transparent;
}

.tooltip:hover .tooltiptext {
  visibility: visible;
  opacity: 1;
}

textarea,textarea:focus,input[type="password"],input[type="password"]:focus,select
{
 font-size: 14px;
 width: 30%;
 padding: 12px 20px;
 box-sizing: border-box;
 border: 4px solid #47110d;
 border-radius: 4px;
 background-color: #f8f8f8;
 outline: none !important;
 box-shadow: 0 0 10px #642e2a;
}

textarea {
 overflow: hidden;
 resize: vertical;
 color: #111;
}

input[type="password"], select {
 color: #111;
}

.button {
  background-color: #ef3d30;
  border: none;
  color: white;
  padding: 10px 20px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 14px;
  border-radius: 8px;
}

.button:hover
{
  background-color: #47110d;
  border: none;
  color: white;
  padding: 10px 20px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 14px;
  border-radius: 8px;
}

.helptext {
  color: #d0d0d0;
  width: 40%;
  line-height: 1.4;
}

.hidden {
  display: none;
}

.status {
  color: #d0d0d0;
  min-height: 22px;
}
</style>
</head>
<body>
<center>
<br>
<img src='/supertechguy-avatar-redeagle.svg' width='100px'>
<br>
HTML;
}

function display_footers()
{
    $iterations = PBKDF2_ITERATIONS;
    $minPassword = MIN_SHARED_SECRET_LENGTH;
    $passwordAttemptLimit = PASSWORD_ATTEMPT_LIMIT_MAX;
    echo <<<HTML
<script>
const PBKDF2_ITERATIONS = {$iterations};
const MIN_SHARED_SECRET_LENGTH = {$minPassword};
const PASSWORD_ATTEMPT_LIMIT_MAX = {$passwordAttemptLimit};
const ASCII_PRINTABLE_PATTERN = /^[ -~]+$/;
const COMMON_PASSWORDS = new Set([
  '12345678','123456789','1234567890','password','password1','password123','qwerty','qwerty123','letmein','welcome','admin','abc123','iloveyou','changeme','secret','passw0rd','11111111','123123123','zaq12wsx','dragon'
]);

function copyFromElement(id, tooltipId, copiedText, defaultText) {
  var copyText = document.getElementById(id);
  if (!copyText) {
    return;
  }
  copyText.select();
  copyText.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(copyText.value);

  var tooltip = document.getElementById(tooltipId);
  if (tooltip) {
    tooltip.innerHTML = copiedText;
    tooltip.dataset.defaultText = defaultText;
  }
}

function resetTooltip(tooltipId) {
  var tooltip = document.getElementById(tooltipId);
  if (tooltip && tooltip.dataset.defaultText) {
    tooltip.innerHTML = tooltip.dataset.defaultText;
  }
}

function bytesToBase64Url(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(base64url) {
  const normalized = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function deriveAesKey(password, saltBytes, iterations) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

function validateSharedPasswordClient(password) {
  if (!password.length) {
    return 'Shared password is required.';
  }
  if (password.length < MIN_SHARED_SECRET_LENGTH) {
    return 'Shared password must be at least ' + MIN_SHARED_SECRET_LENGTH + ' characters long.';
  }
  if (!ASCII_PRINTABLE_PATTERN.test(password)) {
    return 'Shared password must use normal keyboard characters only.';
  }
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return 'Choose a less common shared password.';
  }
  return '';
}

async function encryptClientSide(plaintext, password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(password, salt, PBKDF2_ITERATIONS);
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encoder.encode(plaintext)
  );

  return JSON.stringify({
    v: 1,
    alg: 'AES-GCM',
    kdf: 'PBKDF2-SHA-256',
    iter: PBKDF2_ITERATIONS,
    salt: bytesToBase64Url(salt),
    iv: bytesToBase64Url(iv),
    ct: bytesToBase64Url(new Uint8Array(encrypted))
  });
}

async function decryptClientSide(payload, password) {
  const parsed = JSON.parse(payload);
  if (parsed.v !== 1 || parsed.alg !== 'AES-GCM' || parsed.kdf !== 'PBKDF2-SHA-256') {
    throw new Error('Unsupported encrypted payload format.');
  }

  const salt = base64UrlToBytes(parsed.salt);
  const iv = base64UrlToBytes(parsed.iv);
  const ciphertext = base64UrlToBytes(parsed.ct);
  const key = await deriveAesKey(password, salt, parsed.iter);
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

document.addEventListener('DOMContentLoaded', function () {
  let decryptAttempts = 0;
  const encryptForm = document.getElementById('encrypt-form');
  if (encryptForm) {
    encryptForm.addEventListener('submit', async function (event) {
      event.preventDefault();

      const plaintextField = document.getElementById('plaintext');
      const sharedPasswordField = document.getElementById('SHARED_SECRET');
      const encryptedPayloadField = document.getElementById('encrypted_payload');
      const statusField = document.getElementById('encrypt-status');

      const plaintext = plaintextField.value;
      const sharedPassword = sharedPasswordField.value;
      const passwordError = validateSharedPasswordClient(sharedPassword);

      if (!plaintext.length) {
        statusField.textContent = 'Text is required.';
        return;
      }

      if (passwordError) {
        statusField.textContent = passwordError;
        return;
      }

      try {
        statusField.textContent = 'Encrypting locally in your browser...';
        const payload = await encryptClientSide(plaintext, sharedPassword);
        encryptedPayloadField.value = payload;
        plaintextField.value = '';
        sharedPasswordField.value = '';
        statusField.textContent = 'Submitting encrypted payload...';
        plaintextField.removeAttribute('name');
        sharedPasswordField.removeAttribute('name');
        encryptForm.submit();
      } catch (error) {
        statusField.textContent = 'Client-side encryption failed.';
      }
    });
  }

  const decryptButton = document.getElementById('decrypt-button');
  if (decryptButton) {
    decryptButton.addEventListener('click', async function () {
      const payloadField = document.getElementById('client_encrypted_payload');
      const sharedPasswordField = document.getElementById('decrypt_SHARED_SECRET');
      const outputField = document.getElementById('decrypted_text');
      const outputSection = document.getElementById('decrypted_text_section');
      const statusField = document.getElementById('decrypt-status');

      if (!payloadField || !sharedPasswordField || !outputField || !outputSection || !statusField) {
        return;
      }

      const passwordError = validateSharedPasswordClient(sharedPasswordField.value);
      if (passwordError) {
        statusField.textContent = passwordError;
        return;
      }

      if (decryptAttempts >= PASSWORD_ATTEMPT_LIMIT_MAX) {
        statusField.textContent = 'Too many decrypt attempts on this page. Reload the page to try again.';
        decryptButton.disabled = true;
        return;
      }

      try {
        decryptAttempts++;
        statusField.textContent = 'Decrypting locally in your browser...';
        const decrypted = await decryptClientSide(payloadField.value, sharedPasswordField.value);
        outputField.value = decrypted;
        outputSection.classList.remove('hidden');
        statusField.textContent = 'Decryption complete.';
        sharedPasswordField.value = '';
      } catch (error) {
        statusField.textContent = 'Unable to decrypt. Check the shared password.';
        outputField.value = '';
        outputSection.classList.add('hidden');
      }
    });
  }
});
</script>
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
<textarea id='link' name='link' rows='5' cols='60' autofocus>{$safe_link}</textarea></p>
<div class='tooltip'>
<button class='button' onclick="copyFromElement('link','linkTooltip','Copied link to clipboard','Copy to clipboard')" onmouseout="resetTooltip('linkTooltip')">
  <span class='tooltiptext' id='linkTooltip' data-default-text='Copy to clipboard'>Copy to clipboard</span>
  Copy Link
</button>
</div>
<input class='button' type='button' onclick="location.href='/index.php';" value='Reset' />
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
  <p style='color:red'>[Data Destroyed]</p>
  <div class='tooltip'>
    <button class='button' onclick="copyFromElement('decrypted_text','secretTooltip','Copied text to clipboard','Copy to clipboard')" onmouseout="resetTooltip('secretTooltip')">
      <span class='tooltiptext' id='secretTooltip' data-default-text='Copy to clipboard'>Copy to clipboard</span>
      Copy Text
    </button>
  </div>
  <input class='button' type='button' onclick="location.href='/index.php';" value='Reset' />
</div>
HTML;
}

function display_error($message = '[ERROR]')
{
    $safeMessage = html_escape($message);
    echo <<<HTML
<br>
  <p style='color:red'>{$safeMessage}</p>
  <input class='button' type='button' onclick="location.href='/index.php';" value='Reset' />
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
            enforce_rate_limit('create', CREATE_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS);
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

            $id = $mysqli->insert_id;
            $link = "$project_url/d/$id/$code/$key1/$key2/";
            display_link($link);

            clear_memory($encrypted_payload, $key1, $key2, $code, $encrypted_passwd);
            break;

        case 'decrypt':
            enforce_rate_limit('retrieve', DECRYPT_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS);

            $key1 = validate_ascii_keyboard_text($_GET['key1'] ?? '', 'key1', 128, false);
            $key2 = validate_ascii_keyboard_text($_GET['key2'] ?? '', 'key2', 128, false);
            $id = validate_numeric_id($_GET['id'] ?? '');
            $code = validate_ascii_keyboard_text($_GET['code'] ?? '', 'code', 128, false);

            $now = time();
            $stmt = $mysqli->prepare('SELECT passwd FROM passwds WHERE id=? AND code=? AND expires>?');
            $stmt->bind_param('isi', $id, $code, $now);
            $stmt->execute();
            $stmt->bind_result($encrypted_passwd);
            $stmt->fetch();
            $stmt->close();

            if ($encrypted_passwd) {
                $client_encrypted_payload = secured_decrypt($encrypted_passwd, $key1, $key2);
                if ($client_encrypted_payload !== false) {
                    display_decrypt_form($client_encrypted_payload);
                } else {
                    display_error();
                }
            } else {
                display_error('This link is invalid, expired, or already used.');
            }

            $stmt = $mysqli->prepare('DELETE FROM passwds WHERE id=? AND code=?');
            $stmt->bind_param('is', $id, $code);
            $stmt->execute();
            $stmt->close();

            clear_memory($key1, $key2, $code, $encrypted_passwd, $client_encrypted_payload ?? null);
            break;

        default:
            display_form();
    }

    display_footers();
}

$mysqli->close();
?>
