import test from "node:test";
import assert from "node:assert";
import { SigningHelper } from "../dist/index.js";

function mockFetch(routeFn) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init: init ?? {} });
    const body = routeFn(String(url));
    return { ok: true, status: 200, json: async () => body };
  };
  return { fetchImpl, calls };
}

test("start -> authorize -> complete -> poll, and no secret material leaves the browser", async () => {
  const { fetchImpl, calls } = mockFetch((url) => {
    if (url.includes("/start")) {
      return {
        redirectUrl: "https://connect.acc.cleverbase.com/oauth2/authorize?scope=service&state=s",
        correlationId: "corr-1",
      };
    }
    if (url.includes("/complete")) return { status: "completed" };
    if (url.includes("/status")) return { status: "completed" };
    return {};
  });

  let navigatedTo = null;
  const helper = new SigningHelper({
    startUrl: "https://app.example/api/sign/start",
    completeUrl: "https://app.example/api/sign/complete",
    statusUrl: "https://app.example/api/sign/status",
    fetchImpl,
    navigate: (u) => {
      navigatedTo = u;
    },
  });

  const { redirectUrl, correlationId } = await helper.start({ documentId: "doc-1" });
  assert.ok(redirectUrl.includes("/oauth2/authorize"));
  assert.strictEqual(correlationId, "corr-1");

  helper.goToAuthorization(redirectUrl);
  assert.strictEqual(navigatedTo, redirectUrl);

  const status = await helper.complete("code-xyz", "state-abc");
  assert.strictEqual(status, "completed");

  const polled = await helper.pollStatus(correlationId);
  assert.strictEqual(polled, "completed");

  // US3 / SC-005: the frontend must never carry secrets, tokens, handles, or private keys.
  const forbidden = [
    "client_secret",
    "privatekey",
    "private_key",
    "sad",
    "signhash",
    "session_handle",
    "begin_signing",
  ];
  for (const c of calls) {
    // Scan the whole outbound request — URL, headers, and body — not just the body, since a leak
    // could ride in a query parameter or header.
    const parts = [c.url || ""];
    if (c.init) {
      if (c.init.headers) parts.push(JSON.stringify(c.init.headers));
      if (c.init.body) parts.push(String(c.init.body));
    }
    const haystack = parts.join(" ").toLowerCase();
    for (const word of forbidden) {
      // Word-boundary match so e.g. the SAD token is caught even as `"sad"` in JSON,
      // without false positives on substrings inside unrelated words.
      const re = new RegExp(`\\b${word}\\b`);
      assert.ok(!re.test(haystack), `request to ${c.url} leaked '${word}'`);
    }
  }
});
