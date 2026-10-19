## Summary
<!-- One or two sentences: what vulnerability does this PR fix? -->

## Classification
| | |
|---|---|
| **OWASP Top 10 (2021)** | A0X: Name |
| **CWE** | CWE-XXX |
| **Severity** | Low / Medium / High / Critical |

## Vulnerable code
- **File(s):** `path/to/file.ts` (lines X-Y)
- **Root cause:** <!-- Why is it vulnerable? -->

## Proof of exploit (before)
<!-- Run against v0-vulnerable-baseline or main before this fix -->
```bash
# request
curl ...
```
```
# response showing the exploit works
```

## Fix
<!-- What changed and why it closes the hole. Keep it focused on this one issue. -->

## Proof of fix (after)
```bash
# same request
curl ...
```
```
# response showing the exploit is blocked
```

## Tests
- [ ] New regression test added: `test/...`
- [ ] Test **failed** on the old code and **passes** on the fix
- [ ] Existing tests pass (or failures explained below)

## Pipeline evidence
- [ ] Semgrep (SAST): finding present on baseline, absent on this branch
- [ ] Trivy (SCA) / Gitleaks / Checkov: no new findings
- [ ] DAST: exploit no longer works
- **CI run:** <!-- link -->
- **Baseline run for comparison:** <!-- link -->

## Trade-offs and side effects
<!-- e.g. breaks the Juice Shop scoreboard challenge, changes API behavior, performance impact -->

## Checklist
- [ ] Change is limited to one vulnerability type
- [ ] `SECURITY-FIXES.md` row added or updated
- [ ] Commit message follows `fix(aXX): short description`
- [ ] Self-review done (diff read in GitHub UI)
