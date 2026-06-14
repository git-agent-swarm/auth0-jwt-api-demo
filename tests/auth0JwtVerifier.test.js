import crypto from "node:crypto";
import assert from "node:assert/strict";
import test from "node:test";
import { base64UrlEncode, createAuth0JwtVerifier, JwtVerificationError } from "../src/auth0JwtVerifier.js";

const issuer = "https://dev-kobey-developer.us.auth0.com/";
const audience = "https://api.kobeydev.example";
const now = 1_800_000_000;

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: "demo-key-1",
  alg: "RS256",
  use: "sig",
};

function signJwt(payloadOverrides = {}, headerOverrides = {}) {
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: "demo-key-1",
    ...headerOverrides,
  };
  const payload = {
    iss: issuer,
    aud: audience,
    sub: "auth0|demo-user",
    scope: "read:messages write:drafts",
    exp: now + 300,
    iat: now - 10,
    ...payloadOverrides,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.createSign("RSA-SHA256").update(signingInput).end().sign(privateKey);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

function verifier() {
  return createAuth0JwtVerifier({
    issuer,
    audience,
    now: () => now,
    getKey: async (kid) => (kid === publicJwk.kid ? publicJwk : null),
  });
}

async function rejectsWithCode(promise, code) {
  await assert.rejects(
    promise,
    (error) => error instanceof JwtVerificationError && error.code === code,
  );
}

test("accepts a valid Auth0-style RS256 JWT", async () => {
  const result = await verifier().verify(signJwt(), { requiredScopes: ["read:messages"] });
  assert.equal(result.claims.sub, "auth0|demo-user");
  assert.equal(result.header.kid, "demo-key-1");
});

test("rejects an unexpected issuer", async () => {
  await rejectsWithCode(verifier().verify(signJwt({ iss: "https://evil.example/" })), "bad_issuer");
});

test("rejects an unexpected audience", async () => {
  await rejectsWithCode(verifier().verify(signJwt({ aud: "https://other-api.example" })), "bad_audience");
});

test("accepts audience arrays containing the configured API audience", async () => {
  const result = await verifier().verify(signJwt({ aud: ["https://other.example", audience] }));
  assert.equal(result.claims.aud[1], audience);
});

test("rejects expired tokens", async () => {
  await rejectsWithCode(verifier().verify(signJwt({ exp: now - 60 })), "expired");
});

test("rejects missing required scopes", async () => {
  await rejectsWithCode(
    verifier().verify(signJwt({ scope: "write:drafts" }), { requiredScopes: ["read:messages"] }),
    "missing_scope",
  );
});

test("rejects unsupported algorithms", async () => {
  await rejectsWithCode(verifier().verify(signJwt({}, { alg: "HS256" })), "bad_alg");
});

test("rejects tampered signatures", async () => {
  const token = signJwt();
  const parts = token.split(".");
  parts[1] = base64UrlEncode(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")), sub: "auth0|attacker" }));
  await rejectsWithCode(verifier().verify(parts.join(".")), "bad_signature");
});

test("can fetch and cache a JWKS document", async () => {
  let fetchCount = 0;
  const liveStyleVerifier = createAuth0JwtVerifier({
    issuer,
    audience,
    now: () => now,
    jwksUri: "https://example.test/.well-known/jwks.json",
    fetchImpl: async () => {
      fetchCount += 1;
      return {
        ok: true,
        async json() {
          return { keys: [publicJwk] };
        },
      };
    },
  });

  await liveStyleVerifier.verify(signJwt());
  await liveStyleVerifier.verify(signJwt({ sub: "auth0|second-user" }));
  assert.equal(fetchCount, 1);
});
