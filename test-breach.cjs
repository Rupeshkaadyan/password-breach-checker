/* test-breach.cjs — correctness + privacy proof for the breach-checker engine */
const { sha1Node, splitHash, parseRangeResponse, checkPassword } = require("./breach-checker.cjs");

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log("  PASS  " + name); }
  else { fail++; console.log("  FAIL  " + name + (detail ? "  -> " + detail : "")); }
}

(async () => {
  console.log("\n[1] SHA-1 known vector (NIST test)");
  check("SHA-1('abc')", sha1Node("abc") === "A9993E364706816ABA3E25717850C26C9CD0D89D", sha1Node("abc"));

  console.log("\n[2] splitHash");
  {
    const h = "A9993E364706816ABA3E25717850C26C9CD0D89D";
    const { prefix, suffix } = splitHash(h);
    check("prefix = first 5", prefix === "A9993");
    check("suffix = remaining", suffix === "E364706816ABA3E25717850C26C9CD0D89D");
  }

  console.log("\n[3] parseRangeResponse");
  {
    const body = "ABC123:3\r\nE364706816ABA3E25717850C26C9CD0D89D:42\r\nDEF456:1";
    check("finds matching suffix count", parseRangeResponse(body, "E364706816ABA3E25717850C26C9CD0D89D") === 42,
          "got " + parseRangeResponse(body, "E364706816ABA3E25717850C26C9CD0D89D"));
    check("0 when suffix absent", parseRangeResponse(body, "ZZZZ") === 0);
    check("ignores lines without colon", parseRangeResponse("garbage\nABC123:5", "ABC123") === 5);
  }

  console.log("\n[4] full flow + PRIVACY PROOF (only prefix leaves the device)");
  {
    const pw = "correct horse battery staple";
    const { prefix, suffix } = splitHash(sha1Node(pw));
    const fakeBody = "AAA111:1\r\n" + suffix + ":1337\r\nBBB222:2";
    let sentUrl = null;
    const fakeFetch = async (url) => {
      sentUrl = url;
      if (!url.includes("/range/" + prefix)) throw new Error("URL did not use only the prefix");
      return { ok: true, status: 200, text: async () => fakeBody };
    };
    const res = await checkPassword(pw, { sha1Fn: sha1Node, fetchFn: fakeFetch });
    check("breached = true", res.breached === true);
    check("count = 1337", res.count === 1337, "count=" + res.count);
    check("PRIVACY: request URL contains ONLY the 5-char prefix",
          sentUrl === "https://api.pwnedpasswords.com/range/" + prefix, sentUrl);
    check("PRIVACY: full password/hash never in URL", !sentUrl.includes(suffix));
  }

  console.log("\n[5] safe password (not in mocked list)");
  {
    const pw = "a-very-unique-password-xyz-12345";
    const fakeBody = "AAA111:1\r\nBBB222:2";
    const fakeFetch = async () => ({ ok: true, status: 200, text: async () => fakeBody });
    const res = await checkPassword(pw, { sha1Fn: sha1Node, fetchFn: fakeFetch });
    check("breached = false", res.breached === false);
    check("count = 0", res.count === 0);
  }

  console.log("\n[6] live HIBP API (optional — needs network)");
  try {
    const res = await checkPassword("password", { sha1Fn: sha1Node, fetchFn: fetch });
    check("live: 'password' is breached", res.breached === true, "count=" + res.count);
  } catch (e) {
    console.log("  SKIP  live test (no network in this environment): " + e.message);
  }

  console.log("\n========================================");
  console.log("  RESULT:  " + pass + " passed, " + fail + " failed");
  console.log("========================================\n");
  process.exit(fail ? 1 : 0);
})();
