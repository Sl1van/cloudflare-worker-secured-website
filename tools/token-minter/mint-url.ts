#!/usr/bin/env node
import fs from "node:fs";
import { SignJWT, importPKCS8 } from "jose";

function parseArgs(argv: string[]) {
  const out: any = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    if (!k?.startsWith("--")) continue;
    const key = k.slice(2);
    if (["base","key","aud","path","kid"].includes(key)) { out[key] = v; i++; }
    else if (["minutes","nbf"].includes(key)) { out[key] = Number(v); i++; }
  }
  if (!out.base || !out.minutes || !out.key) {
    console.error("Usage: --base <url> --minutes <n> --key <private.pem>");
    process.exit(1);
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv);
  const baseUrl = new URL(args.base);
  const aud = args.aud || baseUrl.hostname;

  const ttlMin = Math.max(1, Math.floor(args.minutes));
  const nbfMin = args.nbf ?? -1;
  const now = Math.floor(Date.now() / 1000);
  const iat = now;
  const nbf = now + Math.floor(nbfMin * 60);
  const exp = now + ttlMin * 60;

  const privateKeyPem = fs.readFileSync(args.key, "utf8");
  const privateKey = await importPKCS8(privateKeyPem, "ES256");

  const header: any = { alg: "ES256", typ: "JWT" };
  if (args.kid) header.kid = args.kid;

  const payload: any = {};
  if (args.path) payload.path = args.path;

  const jwt = await new SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt(iat)
    .setNotBefore(nbf)
    .setExpirationTime(exp)
    .setAudience(aud)
    .sign(privateKey);

  const url = `${baseUrl.origin}/set-token?t=${encodeURIComponent(jwt)}`;
  console.log(url);
}

main();
