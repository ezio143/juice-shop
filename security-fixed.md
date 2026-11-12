# Security Fixes

This fork of [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is an intentionally vulnerable application. This document tracks the vulnerabilities I have fixed, mapped to the OWASP Top 10 (2021), with evidence for each.

- **Baseline (untouched upstream):** tag [`v0-vulnerable-baseline`](../../releases/tag/v0-vulnerable-baseline)
- **Compare all fixes:** [`v0-vulnerable-baseline...main`](../../compare/v0-vulnerable-baseline...main)

> **Note:** Juice Shop's challenges and scoreboard depend on the flaws existing. Fixing them intentionally breaks the related challenges. That is a deliberate trade-off, noted per fix below.

## How each fix is done

1. Reproduce the exploit on the current code and save the evidence.
2. Write a regression test that fails on the vulnerable code. 
``` node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit --test-name-pattern "JS: Update username with Malicious Code returns sanitized username" test/api/user-profile.test.ts 
```
```
    node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit  test/server/currentUser.unit.test.ts
```
3. Apply a minimal fix, one type of vulnerability per PR.
4. Verify: test passes, exploit blocked, scanner finding gone.
5. Open a PR using the [PR template](.github/pull_request_template.md), run the pipeline (SAST, SCA, DAST), then merge.

## Summary

| # | OWASP 2025 | CWE | Issue | File(s) | PR | Status 
|---|---|---|---|---|---|---|---|
| 1 | A05 Injection | CWE-89 | SQL injection | `routes/login.ts` | #1 | Fixed
| 2 | A05 Injection | CWE-89 | SQL injection | `routes/search.ts` | #2 | Fixed
| 3 | A05 Injection | CWE-89 | Command injection - eval(code)| `routes/userProfile.ts` | #3 | Fixed
| 4 | A06 Insecure Design | CWE-522 | Insuffiecently protected credentials| `routes/CurrentUser.ts` | #4 | Fixed

<!-- Add one row per fix. Status: Planned / In progress / Fixed -->

## Coverage by OWASP category

| Category | Status |
|---|---|
| A01:2025 Broken Access Control | Not started |
| A02:2025 Security Misconfiguration | Not started |
| A03:2025 Software Supply Chain Failures | Not started |
| A04:2025 Cryptographic Failures | Not started |
| A05:2025 Injection | Completed |
| A06:2025 Insecure Design | In Progress |
| A07:2025 Authentication Failures | Not started |
| A08:2025 Software or Data Integrity Failures | Not started |
| A09:2025 Security Logging & Alerting Failures | Not started |
| A10:2025 Mishandling of Exceptional Conditions | Not started |
---


### Fix Template


<!-- Copy the .github/PULL_REQUEST_TEMPLATE for each new fix and add in the details -->