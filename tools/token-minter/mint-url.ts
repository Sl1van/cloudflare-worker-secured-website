#!/usr/bin/env node
import fs from "node:fs";
import { createPrivateKey, sign as nodeSign } from "node:crypto";

/**
 * Mint an Ed25519 (EdDSA) JWT and print a /set-token URL.
 * Requires Node >= 18.7 (Node 20+ recommended).
 *
 * Usage:
 *   pnpm run mint -- --base https://example.com --minutes 30 --key ./ed25519-private.pem
 *
 * Options:
 *   --base     Base URL used to build the /set-token link (required)
 *   --minutes  TTL in minutes (required)
 *   --key      Path to Ed25519 private key in PKCS#8 PEM (required)
 *   --aud      Audience (defaults to the hostname from --base)
 *   --path     Optional custom claim (informational)
 *   --kid      Optional header kid
 *   --nbf      Not-before offset in minutes (default -1 = 1 minute backdate)
 */

type Args = {
  base: string;
  minutes: number;
  key: string;
  aud?: string;
  path?: string;
  kid?: string;
  nbf?: number;
};

function parseArgs(argv: string[]): Args {
  const out: any = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    if (!k?.startsWith("--")) continue;
    const key = k.slice(2);
    if (["base", "key", "aud", "path", "kid"].includes(key)) {
      out[key] = v;
      i++;
    } else if (["minutes", "nbf"].includes(key)) {
      out[key] = Number(v);
      i++;
    }
  }
  if (!out.base || !out.minutes || !out.key) {
    console.error(
      "Usage: --base <url> --minutes <n> --key <ed25519-private.pem>"
    );
    process.exit(1);
  }
  return out as Args;
}

function b64urlEncode(input: Buffer | Uint8Array | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function main() {
  const args = parseArgs(process.argv);
  const baseUrl = new URL(args.base);
  const aud = args.aud || baseUrl.hostname;

  const ttlMin = Math.max(1, Math.floor(args.minutes));
  const nbfMin = args.nbf ?? -1; // small backdate for clock skew
  const now = Math.floor(Date.now() / 1000);
  const iat = now;
  const nbf = now + Math.floor(nbfMin * 60);
  const exp = now + ttlMin * 60;

  // Header & payload
  const header: Record<string, any> = { alg: "EdDSA", typ: "JWT" };
  if (args.kid) header.kid = args.kid;

  const payload: Record<string, any> = { aud, iat, nbf, exp };
  if (args.path) payload.path = args.path;

  const hB64 = b64urlEncode(JSON.stringify(header));
  const pB64 = b64urlEncode(JSON.stringify(payload));
  const data = Buffer.from(`${hB64}.${pB64}`);

  // Load private key (PKCS#8 Ed25519)
  const pem = fs.readFileSync(args.key, "utf8");
  const keyObj = createPrivateKey({ key: pem, format: "pem", type: "pkcs8" });

  // Ed25519: pass null for the digest algorithm
  const sig = nodeSign(null, data, keyObj);
  const sB64 = b64urlEncode(sig);

  const jwt = `${hB64}.${pB64}.${sB64}`;
  const url = `${baseUrl.origin}/set-token?t=${encodeURIComponent(jwt)}`;

  console.log(url);
  console.log(
    `# iat=${iat} nbf=${nbf} exp=${exp} ttl_min=${ttlMin} aud=${aud}${
      args.path ? " path=" + args.path : ""
    }`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
