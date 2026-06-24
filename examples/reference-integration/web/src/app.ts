// No-crypto reference frontend. It drives the signing service through the frontend helper, which
// talks only to this app's own backend (the BFF proxies /api/* to the signing service and injects
// the API key server-side). No secrets, tokens, handles, or keys ever live here.
import { SigningHelper } from "@cleverbase/frontend-helper";

const helper = new SigningHelper({
  startUrl: "/api/v1/sign/start",
  completeUrl: "/api/v1/sign/complete",
  statusUrl: "/api/v1/sign/status",
});

const CORR_KEY = "cleverbase.correlationId";

function startPage(): void {
  const btn = document.getElementById("start") as HTMLButtonElement | null;
  if (!btn) return;
  async function onStart(button: HTMLButtonElement): Promise<void> {
    button.disabled = true;
    try {
      const conformance =
        (document.getElementById("conformance") as HTMLSelectElement | null)?.value ?? "B-B";
      const { redirectUrl, correlationId } = await helper.start({ conformanceLevel: conformance });
      sessionStorage.setItem(CORR_KEY, correlationId);
      helper.goToAuthorization(redirectUrl);
    } catch (e) {
      const out = document.getElementById("out");
      if (out) out.textContent = `Error: ${(e as Error).message}`;
      button.disabled = false;
    }
  }
  // The click handler must return void; `onStart` handles all its own errors internally, so the
  // promise is intentionally not awaited here.
  btn.addEventListener("click", () => void onStart(btn));
}

async function returnPage(): Promise<void> {
  const out = document.getElementById("out");
  if (!out) return;
  const params = new URLSearchParams(location.search);
  const state = params.get("state") ?? "";
  const code = params.get("code");
  const oauthError = params.get("error");

  try {
    const result = code
      ? await helper.complete(code, state)
      : await helper.reportRedirectError(oauthError ?? "unknown_error", state);

    if (result.redirectUrl) {
      // Second (credential-scope / SCAL2) authorization redirect.
      out.textContent = "Authorizing the signature (step 2)…";
      helper.goToAuthorization(result.redirectUrl);
      return;
    }

    out.textContent = `Status: ${result.status}`;
    if (result.status === "completed") {
      const corr = sessionStorage.getItem(CORR_KEY) ?? "";
      const link = document.getElementById("download") as HTMLAnchorElement | null;
      if (link) {
        link.href = `/api/v1/sign/result?correlationId=${encodeURIComponent(corr)}`;
        link.hidden = false;
      }
    }
  } catch (e) {
    out.textContent = `Error: ${(e as Error).message}`;
  }
}

if (document.getElementById("start")) {
  startPage();
} else if (document.getElementById("return-page")) {
  void returnPage();
}
