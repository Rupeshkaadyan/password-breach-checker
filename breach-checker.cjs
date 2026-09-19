/*
 * breach-checker.js
 * Pure, dependency-free core for the Password Breach Checker.
 *
 * Privacy model (k-anonymity, as designed by Troy Hunt / HIBP):
 *   - The password is hashed with SHA-1 IN THIS PROCESS (browser or Node).
 *   - Only the FIRST 5 HEX CHARACTERS of the hash are sent to the API.
 *   - The API returns every hash suffix that shares that prefix; the match is
 *     done locally. The password (and its full hash) never leaves the device.
 *
 * The functions here are environment-agnostic PURE logic so they can be
 * unit-tested without network. The network call is injected (fetchFn) so tests
 * can run offline with a fake response.
 */

// --- Node SHA-1 (used by tests). In the browser we use Web Crypto instead. ---
function sha1Node(s) {
  const crypto = require("crypto");
  return crypto.createHash("sha1").update(s, "utf8").digest("hex").toUpperCase();
}

// Split a SHA-1 hex string into the 5-char prefix and the remaining suffix.
function splitHash(sha1Upper) {
  return { prefix: sha1Upper.slice(0, 5), suffix: sha1Upper.slice(5) };
}

// Parse HIBP's "SUFFIX:COUNT" range response and return the count for `suffix`.
// Returns 0 when the suffix is absent (i.e. not in any known breach).
function parseRangeResponse(body, suffix) {
  const target = String(suffix).toUpperCase();
  const lines = String(body).split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const hash = line.slice(0, idx).trim().toUpperCase();
    const count = parseInt(line.slice(idx + 1), 10);
    if (hash === target) return isNaN(count) ? 0 : count;
  }
  return 0;
}

// Full check. sha1Fn and fetchFn are injected so this is testable offline.
async function checkPassword(password, opts) {
  opts = opts || {};
  const sha1Fn = opts.sha1Fn;
  const fetchFn = opts.fetchFn || (typeof fetch !== "undefined" ? fetch : null);
  if (typeof sha1Fn !== "function") throw new Error("sha1Fn is required");
  if (typeof fetchFn !== "function") throw new Error("fetchFn is required (no network)");

  const hash = sha1Fn(password).toUpperCase();
  const { prefix, suffix } = splitHash(hash);

  // Simple GET (no custom headers => no CORS preflight => most reliable in every browser).
  const res = await fetchFn("https://api.pwnedpasswords.com/range/" + prefix);
  if (!res.ok) throw new Error("HIBP request failed: " + res.status);

  const body = await res.text();
  const count = parseRangeResponse(body, suffix);
  return { hash, prefix, suffix, count, breached: count > 0 };
}

const BreachChecker = { sha1Node, splitHash, parseRangeResponse, checkPassword };
if (typeof module !== "undefined" && module.exports) module.exports = BreachChecker;
