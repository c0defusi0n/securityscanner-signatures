# securityscanner-signatures

Remote regex **signature database** (over-the-air "antivirus definitions") for the
[C0defusi0n Magento SecurityScanner](https://github.com/c0defusi0n/SecurityScanner) module.

The module fetches [`signatures.json`](signatures.json) over HTTPS before each scan and **merges
these patterns on top of** its built-in baseline — they never replace it, so detection still works
offline. Update this file to ship new detections **without releasing the module**.

## Use it

In the Magento admin (*Stores ▸ Configuration ▸ C0DEFUSI0N ▸ Security Scanner ▸ Remote Signatures*):

1. Enable **Remote Signatures**.
2. Set the **Signatures JSON URL** to the raw URL of this file, e.g.
   `https://raw.githubusercontent.com/c0defusi0n/securityscanner-signatures/main/signatures.json`

Fork this repo and point the module at your fork to maintain your own set.

## Format

```json
{
  "version": "2026-06-27",
  "patterns": [
    { "id": "magecart-atob-fetch", "severity": "critical",
      "regex": "/atob\\s*\\([^)]*\\)[^;]*fetch\\s*\\(/is",
      "description": "Base64 payload piped into fetch() — Magecart exfil" }
  ]
}
```

- `regex` is a **full PCRE** with delimiters and flags (`/.../i`). In JSON, backslashes must be
  doubled (`\\s`, `\\(`).
- An invalid pattern is logged and **skipped** — it cannot break the scan. The module caps the
  number of patterns it merges (1000) and the document size.
- Keep `id` stable per detection; bump `version` when you change the set.

## Auto-proposed signatures (review required)

The [`Propose new signatures`](.github/workflows/propose-signatures.yml) GitHub Action runs daily.
It reads the [public vulnerability feed](https://github.com/c0defusi0n/securityscanner-feed), asks the
Gemini API (Google Search grounding) to derive regex **indicators of compromise** for recent Magento /
Adobe Commerce vulnerabilities, and — crucially — **auto-validates** every candidate before proposing it:

- the regex must compile,
- it must match the malicious sample(s) the model provides (so it actually catches the IoC),
- it must **not** match the benign sample(s) (so it won't false-positive on clean stores).

Vetted signatures are added to `signatures.json` and opened as a **pull request** — AI-written
detection is **never merged automatically**. You review the diff (each finding shows its regex,
source, and the samples it was validated against) and merge if it's sound.

> A regex detects *traces of compromise* (injected skimmers, webshells, malicious files) — not
> "this version is vulnerable" (the module checks versions separately). Not every vulnerability
> yields a signature, and that's expected.

### One-time setup

```bash
gh secret set GEMINI_API_KEY --repo c0defusi0n/securityscanner-signatures
# optional model override (default gemini-2.5-flash):
gh variable set GEMINI_MODEL --repo c0defusi0n/securityscanner-signatures --body gemini-2.5-pro
# allow Actions to open PRs in this repo:
gh api -X PUT repos/c0defusi0n/securityscanner-signatures/actions/permissions/workflow \
  -F default_workflow_permissions=write -F can_approve_pull_request_reviews=true
```
