import crypto from "node:crypto";

const DEFAULT_CLOCK_TOLERANCE_SECONDS = 30;

export class JwtVerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "JwtVerificationError";
    this.code = code;
  }
}

export function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function base64UrlDecode(input) {
  const normalized = input.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

function parseJsonPart(part, label) {
  try {
    return JSON.parse(base64UrlDecode(part).toString("utf8"));
  } catch (error) {
    throw new JwtVerificationError("malformed_token", `Invalid JWT ${label}.`);
  }
}

export function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new JwtVerificationError("malformed_token", "Expected a compact JWT with three parts.");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  return {
    encodedHeader,
    encodedPayload,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: base64UrlDecode(encodedSignature),
    header: parseJsonPart(encodedHeader, "header"),
    payload: parseJsonPart(encodedPayload, "payload"),
  };
}

export function publicKeyFromJwk(jwk) {
  if (!jwk || jwk.kty !== "RSA") {
    throw new JwtVerificationError("invalid_jwk", "Expected an RSA JSON Web Key.");
  }
  return crypto.createPublicKey({ key: jwk, format: "jwk" });
}

function assertAudience(payloadAudience, expectedAudience) {
  const audiences = Array.isArray(payloadAudience) ? payloadAudience : [payloadAudience];
  if (!audiences.includes(expectedAudience)) {
    throw new JwtVerificationError("bad_audience", "JWT audience does not match this API.");
  }
}

function assertScopes(scopeClaim, requiredScopes) {
  if (!requiredScopes.length) return;
  const tokenScopes = new Set(String(scopeClaim || "").split(/\s+/u).filter(Boolean));
  const missing = requiredScopes.filter((scope) => !tokenScopes.has(scope));
  if (missing.length) {
    throw new JwtVerificationError("missing_scope", `Missing required scope(s): ${missing.join(", ")}.`);
  }
}

function assertTimeClaims(payload, nowSeconds, toleranceSeconds) {
  if (typeof payload.exp !== "number") {
    throw new JwtVerificationError("missing_exp", "JWT is missing numeric exp claim.");
  }
  if (payload.exp + toleranceSeconds < nowSeconds) {
    throw new JwtVerificationError("expired", "JWT has expired.");
  }
  if (typeof payload.nbf === "number" && payload.nbf - toleranceSeconds > nowSeconds) {
    throw new JwtVerificationError("not_yet_valid", "JWT is not valid yet.");
  }
}

function verifySignature(publicKey, signingInput, signature) {
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(signingInput);
  verifier.end();
  return verifier.verify(publicKey, signature);
}

async function fetchJwks(jwksUri, fetchImpl) {
  const response = await fetchImpl(jwksUri);
  if (!response.ok) {
    throw new JwtVerificationError("jwks_fetch_failed", `JWKS request failed with HTTP ${response.status}.`);
  }
  const jwks = await response.json();
  if (!Array.isArray(jwks.keys)) {
    throw new JwtVerificationError("invalid_jwks", "JWKS response does not include a keys array.");
  }
  return jwks.keys;
}

export function createAuth0JwtVerifier(options) {
  const {
    issuer,
    audience,
    jwksUri,
    getKey,
    fetchImpl = globalThis.fetch,
    now = () => Math.floor(Date.now() / 1000),
    clockToleranceSeconds = DEFAULT_CLOCK_TOLERANCE_SECONDS,
  } = options;

  if (!issuer || !audience) {
    throw new Error("issuer and audience are required.");
  }
  if (!getKey && !jwksUri) {
    throw new Error("Either getKey or jwksUri is required.");
  }

  const keyCache = new Map();

  async function resolveKey(kid) {
    if (!kid) {
      throw new JwtVerificationError("missing_kid", "JWT header is missing kid.");
    }
    if (keyCache.has(kid)) {
      return keyCache.get(kid);
    }

    const jwk = getKey ? await getKey(kid) : (await fetchJwks(jwksUri, fetchImpl)).find((key) => key.kid === kid);
    if (!jwk) {
      throw new JwtVerificationError("unknown_kid", "No JWKS key matched the JWT kid.");
    }

    const publicKey = publicKeyFromJwk(jwk);
    keyCache.set(kid, publicKey);
    return publicKey;
  }

  return {
    async verify(token, verifyOptions = {}) {
      const requiredScopes = verifyOptions.requiredScopes || [];
      const parsed = parseJwt(token);

      if (parsed.header.alg !== "RS256") {
        throw new JwtVerificationError("bad_alg", "Only RS256 JWTs are accepted.");
      }
      if (parsed.payload.iss !== issuer) {
        throw new JwtVerificationError("bad_issuer", "JWT issuer does not match this tenant.");
      }

      assertAudience(parsed.payload.aud, audience);
      assertTimeClaims(parsed.payload, now(), clockToleranceSeconds);
      assertScopes(parsed.payload.scope, requiredScopes);

      const publicKey = await resolveKey(parsed.header.kid);
      if (!verifySignature(publicKey, parsed.signingInput, parsed.signature)) {
        throw new JwtVerificationError("bad_signature", "JWT signature verification failed.");
      }

      return {
        claims: parsed.payload,
        header: parsed.header,
      };
    },
  };
}
