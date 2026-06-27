#!/usr/bin/env python3
"""
Propose new detection signatures from the latest Magento / Adobe Commerce vulnerabilities.

Reads the public vulnerability feed, asks Gemini (with Google Search grounding) to derive regex
signatures for the *indicators of compromise* (injected skimmer JS, webshells, malicious file
patterns) tied to recent vulns, then VETS every candidate locally before writing it: it must
compile, match every "should match" sample, and match none of the "should not match" samples.
Vetted signatures are appended to signatures.json; the workflow opens a PR for human review
(we never auto-merge AI-written detection into the live set).

Pure stdlib — no pip install needed on the runner.
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

MODEL = os.environ.get("GEMINI_MODEL") or "gemini-3.1-flash-lite"
API_URL = "https://generativelanguage.googleapis.com/v1beta/interactions"
SIG_PATH = os.environ.get("SIG_PATH") or "signatures.json"
FEED_URL = os.environ.get("FEED_URL") or "https://raw.githubusercontent.com/c0defusi0n/securityscanner-feed/main/feed.json"
MAX_NEW = int(os.environ.get("MAX_NEW") or "8")
PR_BODY_PATH = "pr_body.md"

# Concepts the module's built-in patterns already cover — don't re-propose these generics.
BUILTIN_COVERED = (
    "eval(, base64_decode(, gzinflate/gzuncompress/str_rot13, assert(, create_function(, "
    "exec/shell_exec/system/passthru/proc_open/popen, preg_replace /e, superglobal-to-sink "
    "($_GET/$_POST/... into eval/system/call_user_func or variable functions), file_put_contents/fwrite "
    "to .ph*, document.write(<script), <script src=external>, display:none div, window.location redirect."
)

SYSTEM = (
    "You are a defensive security engineer writing detection signatures for a Magento store scanner "
    "that scans CMS blocks/pages, configuration HTML, and media file contents for INDICATORS OF "
    "COMPROMISE. You are NOT detecting whether a version is vulnerable (handled elsewhere) — you are "
    "detecting the traces an exploited store would contain: injected card-skimmer JavaScript, PHP "
    "webshells, malicious dropped files, injected external scripts/iframes tied to recent Magento / "
    "Adobe Commerce vulnerabilities and campaigns.\n\n"
    "Rules:\n"
    "1. Use Google Search to find the concrete, public IoCs for the given vulnerabilities (Sansec and "
    "vendor write-ups often publish skimmer code patterns, webshell names, injected markers, domains).\n"
    "2. Only propose a signature when there is a concrete, content-matchable artifact. If a vuln has "
    "no regex-detectable trace, skip it. Quality over quantity — propose nothing rather than guesses.\n"
    "3. Do NOT re-propose generic primitives already covered by the scanner's built-ins: " + BUILTIN_COVERED + "\n"
    "4. Each regex is a full PHP PCRE with / delimiters and flags (e.g. /pattern/is), preg_match-compatible. "
    "Make it SPECIFIC and anchored to the artifact; avoid catastrophic backtracking and avoid broad patterns "
    "that would match legitimate marketing HTML, analytics snippets, or jQuery includes.\n"
    "5. For each signature provide test_should_match (1-3 realistic malicious samples it MUST match) and "
    "test_should_not_match (1-3 benign samples it must NOT match). These are used to auto-validate your regex.\n"
    "Reply with ONLY a compact JSON object, no prose, no markdown fences:\n"
    '{"signatures":[{"id":"slug-or-cve","severity":"critical|high|medium|low","regex":"/.../i",'
    '"description":"what trace this detects","source":"https://...","test_should_match":["..."],'
    '"test_should_not_match":["..."]}]}'
)

FLAG_MAP = {"i": re.I, "s": re.S, "m": re.M, "x": re.X, "u": re.U}


def _collect_text(c):
    """Pull text out of an Interactions content value (string, block, or list of blocks)."""
    if isinstance(c, str):
        return c
    if isinstance(c, dict):
        if isinstance(c.get("text"), str):
            return c["text"]
        return _collect_text(c.get("content"))
    if isinstance(c, list):
        return "".join(_collect_text(x) for x in c)
    return ""


def gemini_text(system, user):
    """One grounded Interactions-API call. Returns the model's final text, or None on no output."""
    key = os.environ["GEMINI_API_KEY"]
    payload = {
        "model": MODEL,
        "input": user,
        "system_instruction": system,
        "tools": [{"type": "google_search"}],   # web search grounding
    }
    req = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), method="POST", headers={
        "x-goog-api-key": key,
        "content-type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            resp = json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"Gemini HTTP {e.code}: {e.read().decode(errors='replace')[:600]}", file=sys.stderr)
        sys.exit(1 if e.code in (400, 401, 403, 404) else 0)
    except Exception as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(0)
    ot = resp.get("output_text")
    if isinstance(ot, str) and ot.strip():
        return ot
    parts = []
    for step in resp.get("steps", []) or []:
        if isinstance(step, dict) and step.get("type") in ("model_output", "model_response", "output"):
            parts.append(_collect_text(step.get("content")))
    text = "".join(p for p in parts if p).strip()
    if text:
        return text
    print("Could not locate model output; response keys=" + ",".join(resp.keys())
          + " | " + json.dumps(resp)[:800], file=sys.stderr)
    return None


def parse_json_object(text):
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def compile_php_regex(rx):
    """Translate a /body/flags PHP PCRE to a compiled Python pattern, or None if invalid/unsupported."""
    if not isinstance(rx, str) or len(rx) < 3 or not rx.startswith("/"):
        return None
    last = rx.rfind("/")
    if last == 0:
        return None
    body, flagstr = rx[1:last], rx[last + 1:]
    flags = 0
    for ch in flagstr:
        if ch in FLAG_MAP:
            flags |= FLAG_MAP[ch]
        elif ch == "a":   # PCRE anchored — harmless to ignore for validation
            continue
        else:
            return None
    try:
        return re.compile(body, flags)
    except re.error:
        return None


def vet(sig, existing_ids, existing_regex):
    """Return a clean signature dict if it passes validation, else None (with a reason printed)."""
    if not isinstance(sig, dict):
        return None
    rx = str(sig.get("regex", "")).strip()
    sid = str(sig.get("id", "")).strip()
    desc = str(sig.get("description", "")).strip()
    sm = sig.get("test_should_match") or []
    nm = sig.get("test_should_not_match") or []
    if not sid or not rx or not desc:
        return None
    if sid in existing_ids or rx in existing_regex:
        print(f"skip {sid}: duplicate")
        return None
    if not isinstance(sm, list) or not isinstance(nm, list) or not sm or not nm:
        print(f"skip {sid}: missing test samples")
        return None
    pat = compile_php_regex(rx)
    if pat is None:
        print(f"skip {sid}: regex does not compile / unsupported")
        return None
    if not all(isinstance(s, str) and pat.search(s) for s in sm):
        print(f"skip {sid}: fails a should-match sample (would miss the IoC)")
        return None
    if any(isinstance(s, str) and pat.search(s) for s in nm):
        print(f"skip {sid}: matches a should-NOT-match sample (false-positive risk)")
        return None
    sev = str(sig.get("severity", "")).strip().lower()
    if sev not in ("critical", "high", "medium", "low"):
        sev = "high"
    return {
        "id": sid, "severity": sev, "regex": rx, "description": desc,
        "source": str(sig.get("source", "")).strip(),
        "_samples": {"match": sm, "no_match": nm},  # for the PR body; stripped before writing
    }


def main():
    try:
        with open(SIG_PATH, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        print(f"Cannot read {SIG_PATH}: {e}", file=sys.stderr)
        sys.exit(1)
    patterns = doc.get("patterns", []) if isinstance(doc, dict) else []
    existing_ids = {str(p.get("id", "")) for p in patterns if isinstance(p, dict)}
    existing_regex = {str(p.get("regex", "")) for p in patterns if isinstance(p, dict)}

    try:
        with urllib.request.urlopen(FEED_URL, timeout=30) as r:
            feed = json.loads(r.read())
        feed_items = feed.get("items", []) if isinstance(feed, dict) else []
    except Exception as e:
        print(f"Cannot read feed ({FEED_URL}): {e}", file=sys.stderr)
        sys.exit(0)
    if not feed_items:
        print("Feed empty; nothing to do.")
        return

    user = (
        "Latest Magento / Adobe Commerce vulnerabilities to derive IoC detection signatures from:\n\n"
        + json.dumps(feed_items, ensure_ascii=False, indent=2)
        + "\n\nSignature ids already present (do not duplicate): "
        + (", ".join(sorted(existing_ids)) or "(none)")
        + f"\n\nResearch their indicators of compromise and propose up to {MAX_NEW} NEW detection "
        "signatures as the JSON object. Output the JSON now."
    )
    data = parse_json_object(gemini_text(SYSTEM, user))
    candidates = (data or {}).get("signatures") if isinstance(data, dict) else None
    if not isinstance(candidates, list) or not candidates:
        print("No candidate signatures returned.")
        return

    vetted = []
    seen = set()
    for c in candidates:
        v = vet(c, existing_ids, existing_regex | {x["regex"] for x in vetted})
        if v and v["id"] not in seen:
            seen.add(v["id"])
            vetted.append(v)
        if len(vetted) >= MAX_NEW:
            break

    if not vetted:
        print("No candidate passed validation; signatures.json unchanged.")
        return

    # Append the vetted signatures (without the internal _samples field) and bump the version.
    for v in vetted:
        patterns.append({k: v[k] for k in ("id", "severity", "regex", "description", "source")})
    doc["patterns"] = patterns
    doc["version"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(SIG_PATH, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")

    with open(PR_BODY_PATH, "w", encoding="utf-8") as f:
        f.write(f"Automated proposal of **{len(vetted)} new detection signature(s)** derived from the "
                "latest Magento / Adobe Commerce vulnerabilities (via Gemini + Google Search). Each one was "
                "auto-validated (compiles, matches its IoC samples, and does **not** match the benign samples "
                "below). **Review before merging** — these run against live stores.\n\n")
        for v in vetted:
            f.write(f"### `{v['id']}` ({v['severity']})\n")
            f.write(f"- **Detects:** {v['description']}\n")
            if v["source"]:
                f.write(f"- **Source:** {v['source']}\n")
            f.write(f"- **Regex:** `{v['regex']}`\n")
            f.write(f"- **Must match:** {json.dumps(v['_samples']['match'], ensure_ascii=False)}\n")
            f.write(f"- **Must NOT match:** {json.dumps(v['_samples']['no_match'], ensure_ascii=False)}\n\n")
    print(f"Wrote {len(vetted)} vetted signature(s) to {SIG_PATH}.")


if __name__ == "__main__":
    main()
