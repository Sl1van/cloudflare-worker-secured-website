// Verifies an ES256 JWT in cookie `token`.
// Allows optional public paths (from env), and /set-token?t=<jwt>.
// All other paths require a valid, unexpired token.

export const onRequest: PagesFunction<{
  PUBKEY_SPKI_PEM: string,      // Public key (SPKI PEM, BEGIN/END PUBLIC KEY)
  ALLOWED_AUD?: string,         // Optional: expected hostname (defaults to request host)
  LEEWAY_S?: string,            // Optional: clock skew leeway (default 60s)
  PUBLIC_PATHS?: string         // Optional: comma-separated list of path prefixes (e.g. "/secret,/docs")
}> = async (ctx) => {
  const url = new URL(ctx.request.url);
  const path = url.pathname;

  // --- 1. Allow public paths (if configured) ---
  const publicPaths = (ctx.env.PUBLIC_PATHS || "")
    .split(",")
    .map(p => p.trim())
    .filter(Boolean);

  if (publicPaths.some(prefix => path === prefix || path.startsWith(prefix + "/"))) {
    const res = await ctx.next();
    res.headers.set("X-Robots-Tag", "noindex, nofollow");
    return res;
  }

  // --- 2. Accept token via query once ---
  if (path === "/set-token") {
    const token = url.searchParams.get("t");
    if (!token) return new Response("Missing token", { status: 400 });

    const res = Response.redirect(url.origin + "/", 302);
    res.headers.append("Set-Cookie", cookie("token", token, { maxAge: 60 * 60 * 24 * 7 }));
    return res;
  }

  // --- 3. Require cookie for everything else ---
  const token = readCookie(ctx.request.headers.get("Cookie") || "", "token");
  if (!token) return notFound();

  const aud = ctx.env.ALLOWED_AUD || url.hostname;
  const leeway = Number(ctx.env.LEEWAY_S || "60");
  const ok = await verifyCompactJWT_ES256(token, ctx.env.PUBKEY_SPKI_PEM, { aud, leeway });

  if (!ok) return notFound();

  return ctx.next();
};

// ---------------- Helpers ----------------

function readCookie(cookieHeader: string, name: string): string | null {
  const m = new RegExp("(?:^|;\\s*)" + name + "=([^;]+)").exec(cookieHeader);
  return m ? m[1] : null;
}

function cookie(name: string, value: string, opts: { maxAge?: number } = {}): string {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  return parts.join("; ");
}

function notFound(): Response {
  return new Response("Not found", { status: 404 });
}

async function verifyCompactJWT_ES256(
  jwt: string,
  pubPem: string,
  opts: { aud?: string; leeway?: number } = {}
): Promise<boolean> {
  try {
    const [hB64, pB64, sB64] = jwt.split(".");
    if (!sB64) return false;

    const header = JSON.parse(atoburl(hB64));
    if (header.alg !== "ES256") return false;

    const payload = JSON.parse(atoburl(pB64));
    const now = Math.floor(Date.now() / 1000);
    const leeway = Math.max(0, opts.leeway ?? 60);

    if (typeof payload.exp !== "number" || now > payload.exp + leeway) return false;
    if (typeof payload.nbf === "number" && now + leeway < payload.nbf) return false;
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
  const b64 = pem.trim().replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "spki",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
}

function atoburl(s: string) { return atob(s.replace(/-/g, "+").replace(/_/g, "/")); }

function fromB64url(s: string): Uint8Array {
  const bin = atoburl(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
