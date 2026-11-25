// Dependency-free Worker/Node verifier. No token contents or provider errors are logged.
const invalid = () => new Error('Invalid upstream identity');
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const text = v => typeof v === 'string' && v.length > 0 && v.length <= 1024;
const integer = v => Number.isSafeInteger(v) && v >= 0;
export const httpsUrl = v => {
  if (!text(v)) throw invalid();
  const u = new URL(v);
  if (u.protocol !== 'https:' || u.username || u.password || u.hash) throw invalid();
  return u;
};
function decode(part) {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) throw invalid();
  return Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
function parse(part) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(part)));
  if (!object(value)) throw invalid();
  return value;
}
export async function boundedJson(response) {
  if (!response.ok || !response.body) throw invalid();
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 65536) throw invalid();
      chunks.push(value);
    }
  } catch (error) {
    try { await reader.cancel(); } catch { /* preserve original failure */ }
    throw error;
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
/** Verify a Cloudflare SaaS OIDC ID token, not an MCP bearer token. */
export async function verifyAccessIdToken(token, config, fetcher = fetch, now = Math.floor(Date.now() / 1000)) {
  try {
    if (!object(config) || !text(config.clientId) || !integer(now)) throw invalid();
    httpsUrl(config.issuer);
    const jwks = httpsUrl(config.jwksUrl);
    if (typeof token !== 'string' || token.length > 16384) throw invalid();
    const parts = token.split('.');
    if (parts.length !== 3) throw invalid();
    const header = parse(parts[0]);
    const claims = parse(parts[1]);
    const signature = decode(parts[2]);
    if (header.alg !== 'RS256' || !text(header.kid) || 'crit' in header || 'b64' in header) throw invalid();
    // Exact configured issuer and one audience: this integration has one client.
    const aud = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
    if (claims.iss !== config.issuer || !Array.isArray(aud) || aud.length !== 1 || aud[0] !== config.clientId) throw invalid();
    if ('azp' in claims && claims.azp !== config.clientId) throw invalid();
    if (!integer(claims.exp) || !integer(claims.iat) || claims.exp <= now || claims.iat > now + 60 || claims.exp <= claims.iat) throw invalid();
    if ('nbf' in claims && (!integer(claims.nbf) || claims.nbf > now + 60 || claims.nbf >= claims.exp)) throw invalid();
    if (!text(claims.sub) || !text(claims.email) || !/^[^\s@]+@[^\s@]+$/.test(claims.email)) throw invalid();
    if ('email_verified' in claims && claims.email_verified !== true) throw invalid();
    const response = await fetcher(jwks.href, { redirect: 'error', signal: AbortSignal.timeout(5000), headers: { Accept: 'application/json' } });
    const keys = await boundedJson(response);
    if (!object(keys) || !Array.isArray(keys.keys) || keys.keys.length > 100) throw invalid();
    const matches = keys.keys.filter(k => object(k) && k.kid === header.kid);
    if (matches.length !== 1) throw invalid();
    const key = matches[0];
    if (key.kty !== 'RSA' || ('alg' in key && key.alg !== 'RS256') || ('use' in key && key.use !== 'sig') || ('key_ops' in key && (!Array.isArray(key.key_ops) || !key.key_ops.includes('verify'))) || decode(key.n).byteLength < 256) throw invalid();
    const publicKey = await crypto.subtle.importKey('jwk', key, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, new TextEncoder().encode(`${parts[0]}.${parts[1]}`))) throw invalid();
    return {
      sub: claims.sub,
      email: claims.email,
      emailVerified: claims.email_verified === true,
      name: text(claims.name) ? claims.name : 'Authenticated user',
    };
  } catch { throw invalid(); }
}
