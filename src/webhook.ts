// GitHub webhook signature check (HMAC-SHA256, X-Hub-Signature-256), constant-time.

const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

export async function verifySignature(secret: string, body: string, header: string | null): Promise<boolean> {
  if (!secret || !header || !header.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = `sha256=${hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)))}`;
  if (expected.length !== header.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ header.charCodeAt(i);
  return diff === 0;
}
