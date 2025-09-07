# cloudflare-worker-secured-website

This is a minimal example of how to protect a static website hosted on **Cloudflare Pages** with a **signed, time-limited access token**.  
The protection is implemented using a Cloudflare **Pages Function middleware** that checks a cookie named `token` containing a signed JWT.  

A separate Node.js script (`tools/token-minter`) is provided to mint valid URLs that set the cookie and grant temporary access.

## ⚠️ Security Notice

**This code is provided for educational and demonstration purposes only.**

- **Do NOT use this to protect sensitive, confidential, or critical data**
- This implementation has NOT been security audited or tested
- It provides basic access control, not robust security
- Suitable only for simple use cases like hiding work-in-progress sites from public view
- For production applications with sensitive data, use proper authentication services

If you need to protect sensitive data, consider using established authentication providers like Auth0, AWS Cognito, Firebase Auth, or similar services.

---

## How it works

1. The website is hosted as a normal Cloudflare Pages project.  
2. A Pages Function (`functions/_middleware.ts`) intercepts all requests.  
   - If the request path is in the list of `PUBLIC_PATHS`, it is allowed without authentication.  
   - If the request is `/set-token?t=<jwt>`, the function sets a cookie called `token` with the given JWT and redirects to the homepage.  
   - For all other paths, the middleware validates the JWT in the `token` cookie.  
3. The JWT is signed offline (or by a separate Worker) with an ES256 private key.  
4. The middleware verifies the signature using the public key, and enforces `exp` (expiry), `nbf` (not before), and `aud` (audience/hostname).  
5. When the token expires, access automatically stops until a new token is issued.

This approach is **not meant to be high-security authentication**, but it’s a simple way to keep a site private from the general public without adding a login screen or third-party auth.

---

## Generate ed25519 PEM keys

These keys will be used in the middleware (public key) and by the token-minter script (private key) to generate signed access tokens.

```bash
# Private (PKCS#8)
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem

# Public (SPKI)
openssl pkey -in ed25519-private.pem -pubout -out ed25519-public.pem
```

## Creating a URL with an access token

Use the Node.js script in `tools/token-minter` to mint a short-lived signed JWT and embed it in a `/set-token` link.

Example: create a token valid for 30 minutes:

```bash
cd tools/token-minter
pnpm install
pnpm run mint -- --base https://example.com --minutes 30 --key ./ed25519-private.pem
```

The script will print a URL like:
```
https://example.com/set-token?t=<long.jwt.token>
```
Opening this URL in a browser sets the token cookie and redirects to /.
After the expiry time, the JWT becomes invalid and access is denied.


## Configuring the middleware
In your Cloudflare Pages project, configure the following *environment variables*:
 * `PUBKEY_SPKI_PEM` - your public key in SPKI PEM format (the contents of `es256-public.pem`).
 * `PUBLIC_PATHS` - optional, comma-separated list of paths that remain public:
 ```
 PUBLIC_PATHS="/secret,/docs,/faq"
 ```
 * `ALLOWED_AUD` (optional) — restrict tokens to a specific audience/hostname. Defaults to the request host.
 * `LEEWAY_S` (optional) — allowed clock skew in seconds (default: 60).
 