# Security Fixes

This fork of [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is an intentionally vulnerable application. This document tracks the vulnerabilities I have fixed, mapped to the OWASP Top 10 (2021), with evidence for each.

- **Baseline (untouched upstream):** tag [`v0-vulnerable-baseline`](../../releases/tag/v0-vulnerable-baseline)
- **Compare all fixes:** [`v0-vulnerable-baseline...main`](../../compare/v0-vulnerable-baseline...main)

> **Note:** Juice Shop's challenges and scoreboard depend on the flaws existing. Fixing them intentionally breaks the related challenges. That is a deliberate trade-off, noted per fix below.

## How each fix is done

1. Reproduce the exploit on the current code and save the evidence.
2. Write a regression test that fails on the vulnerable code.
3. Apply a minimal fix, one type of vulnerability per PR.
4. Verify: test passes, exploit blocked, scanner finding gone.
5. Open a PR using the [PR template](.github/pull_request_template.md), run the pipeline (SAST, SCA, DAST), then merge.

## Summary

| # | OWASP 2021 | CWE | Issue | File(s) | PR | Status | Evidence |
|---|---|---|---|---|---|---|---|
| 1 | A03 Injection | CWE-89 | SQL injection | `routes/login.ts` | #1 | Fixed | TBD |

<!-- Add one row per fix. Status: Planned / In progress / Fixed -->

## Coverage by OWASP category

| Category | Status |
|---|---|
| A01 Broken Access Control | Not started |
| A02 Cryptographic Failures | Not started |
| A03 Injection | In progress |
| A04 Insecure Design | Not started |
| A05 Security Misconfiguration | Not started |
| A06 Vulnerable and Outdated Components | Not started |
| A07 Identification and Authentication Failures | Not started |
| A08 Software and Data Integrity Failures | Not started |
| A09 Security Logging and Monitoring Failures | Not started |
| A10 Server-Side Request Forgery | Not started |

---


### Fix Template


### 1. SQL injection in login (A03, CWE-89)

- **PR:** #TBD
- **Vulnerable code:** `routes/login.ts`: user input is concatenated directly into a raw SQL query.
- **Exploit (before):** TBD (login request with a crafted email payload returns an authenticated session)
- **Fix:** TBD (parameterized query / bound replacements)
- **Exploit (after):** TBD (same request is rejected)
- **Regression test:** `test/api/...` TBD
- **Scanner evidence:** TBD (Semgrep finding present on baseline run [link], absent on fix run [link])
- **Trade-offs:** Breaks the related Juice Shop login challenge(s) by design.

<!-- Copy the block above for each new fix -->
