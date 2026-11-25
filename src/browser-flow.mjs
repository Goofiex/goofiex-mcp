const invalid = () => new Error('Invalid authorization request');
const stateFormat = /^[0-9a-f-]{36}\.[0-9a-f]{64}$/i;
const csrfFormat = /^[0-9a-f-]{36}$/i;
const cookieName = '__Host-OAUTH_STATE';
export function canonicalOrigin(resource, requestUrl) {
  const configured = new URL(resource);
  if (configured.protocol !== 'https:' || configured.username || configured.password || configured.pathname !== '/mcp' || configured.search || configured.hash) throw invalid();
  if (new URL(requestUrl).origin !== configured.origin) throw invalid();
  return configured.origin;
}
export function callbackState(request) {
  const state = new URL(request.url).searchParams.getAll('state');
  const cookies = (request.headers.get('cookie') || '').split(';').map(v => v.trim()).filter(v => v.startsWith(`${cookieName}=`));
  if (state.length !== 1 || !stateFormat.test(state[0]) || cookies.length !== 1 || cookies[0].slice(cookieName.length+1) !== state[0]) throw invalid();
  return state[0];
}
export function stateCookie(state) {
  if (!stateFormat.test(state)) throw invalid();
  return `${cookieName}=${state}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600`;
}
export const clearStateCookie = () => `${cookieName}=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0`;
export async function readApprovalForm(request, origin) {
  if (request.method !== 'POST' || request.headers.get('origin') !== origin || new URL(request.url).origin !== origin || !/^application\/x-www-form-urlencoded(?:\s*;.*)?$/i.test(request.headers.get('content-type') || '')) throw invalid();
  const length = request.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > 4096)) throw invalid();
  if (!request.body) throw invalid();
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 4096) throw invalid();
      chunks.push(value);
    }
  } catch (error) {
    try { await reader.cancel(); } catch { /* preserve rejection */ }
    throw invalid();
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const form = new URLSearchParams(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  const tokens = form.getAll('csrf_token');
  if (tokens.length !== 1 || !csrfFormat.test(tokens[0])) throw invalid();
  const result = new FormData();
  result.set('csrf_token', tokens[0]);
  return result;
}
