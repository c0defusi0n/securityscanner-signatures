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
