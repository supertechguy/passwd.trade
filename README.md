# passwd.trade

passwd.trade is a secure one-time text transfer service designed to self-destruct after a single use.

## What Technologies Do We Use?

We use Apache, PHP, MySQL, and the browser Web Crypto API to power this project.

## How Do We Keep Your Data Safe?

The app uses two encryption layers:

1. The sender's browser encrypts the text locally using AES-256-GCM through the Web Crypto API.
2. The server then encrypts that already-encrypted payload again using AES-256-CBC with HMAC-SHA3-512.

The shared browser secret is never sent to the server. It must be delivered to the recipient separately.

## Security Hardening Included

This version adds a number of practical security improvements without changing the basic design:

- CSRF protection on the create form
- Security headers including HSTS, CSP, no-referrer, nosniff, and clickjacking protection
- Rate limiting for create and retrieve requests
- Short-lived expiration options of 15 minutes, 1 hour, or 24 hours
- Automatic cleanup of expired records
- Client-side shared-password checks with a minimum length and a small common-password blocklist
- Input size limits for the secret and encrypted payload
- Reduced sensitive logging behavior so plaintext and encrypted payloads are not written to server logs

## How Do You Use It?

1. Enter the password you want to send.
2. Enter a shared secret using normal keyboard characters.
3. Choose an expiration time.
4. Click **Generate Link**.
5. Send the link to your recipient.
6. Share the secret with the recipient through a different channel.
7. The recipient opens the link, enters the shared secret, and clicks **Decrypt**.

## Security Notes

- The server never receives the shared secret.
- The one-time link still carries the server-side decryption keys for the outer encryption layer.
- Anyone with the link can retrieve the browser-encrypted payload once, but they still need the out-of-band shared password to read the text.
- After retrieval, the stored server copy is destroyed.

## Important Tradeoff

The project intentionally keeps the server from holding everything needed to remove the outer encryption by itself. That means the link remains sensitive and should be handled carefully.

## How Can You Contribute?

If you'd like to contribute to this project, please reach out to @supertechguy.

## What Are the Licensing Terms?

This project is distributed under the GNU General Public License version 2.

