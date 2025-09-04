// Cloudflare Pages Function middleware to gate your site with a signed, time-limited JWT.
// - Public paths are configurable via env PUBLIC_PATHS (comma-separated prefixes, optional).
// - Cookie name is configurable via env TOKEN_COOKIE_NAME (defaults to "token").
// - JWT is ES256-signed elsewhere; this middleware only verifies using PUBKEY_SPKI_PEM.
//
// Required env:
//   PUBKEY_SPKI_PEM: string  (SPKI PEM public key, including BEGIN/END lines)
// Optional env:
//   PUBLIC_PATHS: string     (e.g. "/secret,/docs,/faq")
//   ALLOWED_AUD: string      (expected hostname; defaults to request host)
//   LEEWAY_S: string         (clock skew leeway in seconds; default 60)
//   TOKEN_COOKIE_NAME: string (cookie name; default "token")


export const onRequest: PagesFunction<{
  PUBKEY_SPKI_PEM: string;
  PUBLIC_PATHS?: string;
  ALLOWED_AUD?: string;
  LEEWAY_S?: string;
  TOKEN_COOKIE_NAME?: string;
}> = async (ctx) => {
  const url = new URL(ctx.request.url);
  const path = url.pathname;

  const COOKIE_NAME = ctx.env.TOKEN_COOKIE_NAME || "token";
  const aud = ctx.env.ALLOWED_AUD || url.hostname;
  const leeway = Number(ctx.env.LEEWAY_S || "60");

  // --- 1) Allow public paths (if configured) ---
  const publicPaths = (ctx.env.PUBLIC_PATHS || "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);

  if (publicPaths.some((prefix) => path === prefix || path.startsWith(prefix + "/"))) {
    const res = await ctx.next();
    return withHeader(res, "X-Robots-Tag", "noindex, nofollow");
  }

  // --- 2) Accept token via query once; set cookie and redirect to "/" ---
  if (path === "/set-token") {
    const token = url.searchParams.get("t");
    if (!token) return new Response("Missing token", { status: 400 });

    // Build a fresh Response with our own headers (no mutation of immutable headers).
    const headers = new Headers();
    headers.set("Location", url.origin + "/");
    headers.append(
      "Set-Cookie",
      cookie(COOKIE_NAME, token, { maxAge: 60 * 60 * 24 * 7 })
    );
    return new Response(null, { status: 302, headers });
  }

  // --- 3) Require a valid token cookie for everything else ---
  const token = readCookie(ctx.request.headers.get("Cookie") || "", COOKIE_NAME);
  if (!token) return notFound();

  const ok = await verifyCompactJWT_ES256(token, ctx.env.PUBKEY_SPKI_PEM, { aud, leeway });
  if (!ok) return notFound();

  return ctx.next();
};

/* ---------------- Helpers ---------------- */

function readCookie(cookieHeader: string, name: string): string | null {
  const m = new RegExp("(?:^|;\\s*)" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]+)").exec(
    cookieHeader
  );
  return m ? m[1] : null;
}

function cookie(
  name: string,
  value: string,
  opts: { maxAge?: number } = {}
): string {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  return parts.join("; ");
}

function notFound(): Response {
  // Use 404 for "stealth" (change to 403 if you prefer explicit denial)
  return new Response("Not found", { status: 404 });
}

function withHeader(res: Response, key: string, value: string): Response {
  const headers = new Headers(res.headers);
  headers.set(key, value);
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
}

async function verifyCompactJWT_ES256(
  jwt: string,
  pubPem: string,
  opts: { aud?: string; leeway?: number } = {}
): Promise<boolean> {
  try {
    const [hB64, pB64, sB64] = jwt.split(".");
    if (!hB64 || !pB64 || !sB64) return false;

    const header = JSON.parse(atoburl(hB64));
    if (header.alg !== "ES256") return false;

    const payload = JSON.parse(atoburl(pB64));
    const now = Math.floor(Date.now() / 1000);
    const leeway = Math.max(0, opts.leeway ?? 60);

    // Time checks
    if (typeof payload.exp !== "number" || now > payload.exp + leeway) return false;
    if (typeof payload.nbf === "number" && now + leeway < payload.nbf) return false;

    // Audience check (lock to hostname)
    if (opts.aud && payload.aud && payload.aud !== opts.aud) return false;

    const key = await importSpki(pubPem);
    const data = new TextEncoder().encode(`${hB64}.${pB64}`);
    const sig = fromB64url(sB64);

    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, data);
  } catch {
    return false;
  }
}

async function importSpki(pem: string) {
  const b64 = pem
    .trim()
    .replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "spki",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
}

function atoburl(s: string): string {
  return atob(s.replace(/-/g, "+").replace(/_/g, "/"));
}

function fromB64url(s: string): Uint8Array {
  const bin = atoburl(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(0);
  return arr;
}
