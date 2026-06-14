import http from "node:http";
import { createAuth0JwtVerifier, JwtVerificationError } from "./auth0JwtVerifier.js";

const issuer = process.env.AUTH0_ISSUER;
const audience = process.env.AUTH0_AUDIENCE;
const jwksUri = process.env.AUTH0_JWKS_URI;
const port = Number(process.env.PORT || 8787);

function json(res, statusCode, payload) {
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload, null, 2));
}

function bearerToken(req) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/iu);
  return match ? match[1] : null;
}

if (!issuer || !audience || !jwksUri) {
  console.error("Missing AUTH0_ISSUER, AUTH0_AUDIENCE, or AUTH0_JWKS_URI.");
  process.exitCode = 2;
} else {
  const verifier = createAuth0JwtVerifier({ issuer, audience, jwksUri });

  const server = http.createServer(async (req, res) => {
    if (req.url === "/health") {
      json(res, 200, { ok: true, service: "auth0-jwt-api-demo" });
      return;
    }

    if (req.url === "/api/private") {
      const token = bearerToken(req);
      if (!token) {
        json(res, 401, { error: "missing_bearer_token" });
        return;
      }

      try {
        const result = await verifier.verify(token, { requiredScopes: ["read:messages"] });
        json(res, 200, {
          ok: true,
          subject: result.claims.sub,
          scopes: String(result.claims.scope || "").split(/\s+/u).filter(Boolean),
        });
      } catch (error) {
        if (error instanceof JwtVerificationError) {
          json(res, 401, { error: error.code, message: error.message });
          return;
        }
        json(res, 500, { error: "verification_failed" });
      }
      return;
    }

    json(res, 404, { error: "not_found" });
  });

  server.listen(port, () => {
    console.log(`Auth0 JWT API demo listening on http://localhost:${port}`);
  });
}
