import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyAccessIdToken, httpsUrl, boundedJson } from '../src/oidc-verify.mjs';
const now = 1800000000;
const cfg = { issuer: 'https://idp.example.test', clientId: 'synthetic-client', jwksUrl: 'https://idp.example.test/jwks' };
const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign','verify']);
const jwk = { ...await crypto.subtle.exportKey('jwk', pair.publicKey), kid: 'fixture-key', alg: 'RS256', use: 'sig' };
const header = { alg: 'RS256', kid: jwk.kid };
const claims = { iss: cfg.issuer, aud: cfg.clientId, exp: now+300, iat: now-10, sub:'synthetic-subject', email:'owner@example.test' };
const enc = v => Buffer.from(JSON.stringify(v)).toString('base64url');
async function sign(c = claims, h = header) {
  const data = `${enc(h)}.${enc(c)}`;
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, Buffer.from(data));
  return `${data}.${Buffer.from(sig).toString('base64url')}`;
}
const fetcher = async (url, opts) => {
  assert.equal(url, cfg.jwksUrl); assert.equal(opts.redirect, 'error');
  return Response.json({ keys: [jwk] });
};
const verify = (token, config=cfg, f=fetcher) => verifyAccessIdToken(token, config, f, now);
test('valid signed token', async () => assert.deepEqual(await verify(await sign()), {sub:claims.sub,email:claims.email,emailVerified:false,name:'Authenticated user'}));
test('verified email is separately attested', async () => assert.equal((await verify(await sign({...claims,email_verified:true}))).emailVerified,true));
test('one-element audience array', async () => assert.equal((await verify(await sign({...claims,aud:[cfg.clientId]}))).sub,claims.sub));
for (const [name, patch] of Object.entries({ wrongIssuer:{iss:'https://other.example.test'}, wrongAudience:{aud:'other'}, multipleAudiences:{aud:[cfg.clientId,'other']}, wrongAzp:{azp:'other'}, missingExp:{exp:undefined}, invalidExp:{exp:'1800000300'}, expired:{exp:now}, missingIat:{iat:undefined}, futureIat:{iat:now+61}, futureNbf:{nbf:now+61}, invalidNbf:{nbf:'later'}, invalidSubject:{sub:''}, badEmail:{email:'not-email'}, unverifiedEmail:{email_verified:false} })) {
  test(name, async () => assert.rejects(verify(await sign({...claims,...patch})), /Invalid upstream identity/));
}
for(const [name,patch] of Object.entries({wrongAlgorithm:{alg:'HS256'},unknownKid:{kid:'other'},unsupportedCriticalHeader:{crit:['custom']},invalidKid:{kid:42},unencodedPayload:{b64:false}})) {
  test(name, async () => assert.rejects(verify(await sign(claims,{...header,...patch})), /Invalid upstream identity/));
}
test('missing config fails closed',async()=>assert.rejects(verify(await sign(),{...cfg,issuer:undefined}),/Invalid upstream identity/));
test('non HTTPS JWKS fails closed',async()=>assert.rejects(verify(await sign(),{...cfg,jwksUrl:'http://idp.example.test/jwks'}),/Invalid upstream identity/));
test('malformed token',async()=>assert.rejects(verify('a.b.c'),/Invalid upstream identity/));
test('oversize token',async()=>assert.rejects(verify('a'.repeat(16385)),/Invalid upstream identity/));
test('tampered signature',async()=>{const t=await sign();const parts=t.split('.');parts[2]=(parts[2][0]==='A'?'B':'A')+parts[2].slice(1);await assert.rejects(verify(parts.join('.')), /Invalid upstream identity/);});
test('duplicate kid',async()=>assert.rejects(verify(await sign(),cfg,async()=>Response.json({keys:[jwk,jwk]})),/Invalid upstream identity/));
test('bad key usage',async()=>assert.rejects(verify(await sign(),cfg,async()=>Response.json({keys:[{...jwk,use:'enc'}]})),/Invalid upstream identity/));
test('provider failure is sanitized',async()=>assert.rejects(verify(await sign(),cfg,async()=>new Response('sensitive synthetic body',{status:502})),{message:'Invalid upstream identity'}));
test('oversized JWKS rejected',async()=>assert.rejects(verify(await sign(),cfg,async()=>new Response('x'.repeat(65537))),/Invalid upstream identity/));
test('upstream URL rejects credentials and fragments',()=>{assert.throws(()=>httpsUrl('https://user:pass@idp.example.test/token'));assert.throws(()=>httpsUrl('https://idp.example.test/token#fragment'));});
test('upstream response bound applies to exchange too',async()=>{assert.deepEqual(await boundedJson(Response.json({id_token:'synthetic'})),{id_token:'synthetic'});await assert.rejects(boundedJson(new Response('x'.repeat(65537))));});
