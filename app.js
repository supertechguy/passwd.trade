(function () {
  const body = document.body.dataset;
  const PBKDF2_ITERATIONS = parseInt(body.pbkdf2Iterations, 10);
  const MIN_SHARED_SECRET_LENGTH = parseInt(body.minSecretLength, 10);
  const PASSWORD_ATTEMPT_LIMIT_MAX = parseInt(body.attemptLimit, 10);
  const ASCII_PRINTABLE_PATTERN = /^[ -~]+$/;
  const COMMON_PASSWORDS = new Set([
    '12345678', '123456789', '1234567890', 'password', 'password1', 'password123',
    'qwerty', 'qwerty123', 'letmein', 'welcome', 'admin', 'abc123', 'iloveyou',
    'changeme', 'secret', 'passw0rd', '11111111', '123123123', 'zaq12wsx', 'dragon'
  ]);

  function copyFromElement(id, tooltipId, copiedText, defaultText) {
    const el = document.getElementById(id);
    if (!el) return;
    el.select();
    el.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(el.value);
    const tooltip = document.getElementById(tooltipId);
    if (tooltip) {
      tooltip.innerHTML = copiedText;
      tooltip.dataset.defaultText = defaultText;
    }
  }

  function resetTooltip(tooltipId) {
    const tooltip = document.getElementById(tooltipId);
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
      { name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  function validateSharedPasswordClient(password) {
    if (!password.length) return 'Shared password is required.';
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
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encoder.encode(plaintext));
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
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
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
        if (!plaintext.length) { statusField.textContent = 'Text is required.'; return; }
        if (passwordError) { statusField.textContent = passwordError; return; }
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
        if (!payloadField || !sharedPasswordField || !outputField || !outputSection || !statusField) return;
        const passwordError = validateSharedPasswordClient(sharedPasswordField.value);
        if (passwordError) { statusField.textContent = passwordError; return; }
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

    const copyLinkBtn = document.getElementById('copy-link-btn');
    if (copyLinkBtn) {
      copyLinkBtn.addEventListener('click', function () {
        copyFromElement('link', 'linkTooltip', 'Copied link to clipboard', 'Copy to clipboard');
      });
      copyLinkBtn.addEventListener('mouseout', function () { resetTooltip('linkTooltip'); });
    }

    const copyTextBtn = document.getElementById('copy-text-btn');
    if (copyTextBtn) {
      copyTextBtn.addEventListener('click', function () {
        copyFromElement('decrypted_text', 'secretTooltip', 'Copied text to clipboard', 'Copy to clipboard');
      });
      copyTextBtn.addEventListener('mouseout', function () { resetTooltip('secretTooltip'); });
    }

    document.querySelectorAll('.reset-btn').forEach(function (btn) {
      btn.addEventListener('click', function () { location.href = '/index.php'; });
    });
  });
})();
