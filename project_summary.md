## Project 1 — SAST / DAST / SCA Pipeline

A GitHub Actions pipeline wiring three distinct vulnerability-scanning categories into a fork of OWASP Juice Shop, with a deliberate, documented gating strategy rather than a uniform "block everything" approach.

### 1. SAST — GitHub CodeQL

**Before:** No static analysis of the application's own source code — vulnerabilities written directly into the codebase (as opposed to pulled in via a dependency) had no automated detection at all.

**Setup:** `github/codeql-action/init`, `autobuild`, `analyze`, targeting `javascript-typescript`. Requires `security-events: write` permission to publish results to the repo's Security tab — without it, the scan runs but silently fails to publish.

**How it works:** Data-flow (taint) analysis — traces untrusted input from where it enters the app ("source") to where it's used dangerously ("sink"), flagging paths with no sanitization in between.

**Gating decision:** Report-only. CodeQL surfaces findings via the Security tab but doesn't block merges — chosen to establish visibility first, without the friction of gating on a tool whose false-positive rate hadn't yet been characterized on this codebase.

**Real finding — Critical NoSQL Injection (`routes/showProductReviews.ts:36`):** User-supplied input flows unsanitized into a MongoDB query, allowing an attacker to manipulate query *logic* (via MongoDB operators) rather than just the intended search term — the NoSQL equivalent of classic SQL injection. Confirmed via CodeQL's taint-flow analysis (HTTP request input → MongoDB query execution, no sanitization between). Left unpatched since it's one of Juice Shop's documented training challenges, but the pipeline correctly surfaced it.

### 2. SCA — Dependabot + Snyk

**Before:** No automated visibility into known-vulnerable third-party dependencies.

**Why two tools:** Dependabot (GitHub-native, free) uses the GitHub Advisory Database and passively opens PRs. Snyk maintains its own vulnerability database — sometimes earlier/broader coverage — and, critically, is configured to **actively fail the build** (`--severity-threshold=high`), which Dependabot alone does not do. Running both demonstrates awareness that different vulnerability databases have different coverage; in most production environments, teams standardize on one primary tool rather than running both long-term — this is a deliberate portfolio choice to show breadth, not a "best practice you'd always do in prod."

**Gating decision:** Snyk is the pipeline's **only hard gate**, on High/Critical severity. This is the highest-confidence, lowest-noise signal available (known CVEs against a fixed threshold), making it the safest candidate for build-blocking.

**Real finding — Authorization Bypass (`express-jwt@0.1.3`, High):** A very old JWT authentication middleware version with a flaw allowing crafted tokens to bypass validation entirely — about as serious as an app-security finding gets. Correctly failed the build under the severity gate, confirming the gate functions as intended. Broader scan run: 814 dependencies tested, 44 issues, 61 vulnerable paths, including several with **no available upgrade or patch** (e.g., `decompress`, `libxmljs2`, `marsdb`) — a realistic scenario requiring risk-acceptance or a package swap rather than a simple version bump.

### 3. DAST — OWASP ZAP

**Before:** No testing of the application's actual runtime behavior — SAST/SCA analyze code and dependency metadata, neither executes the app.

**Setup:** Builds the Docker image from this fork's own `Dockerfile` (not the public upstream image — a deliberate choice so the pipeline scans what was actually built, not a random external artifact), runs it, then `zaproxy/action-baseline` attacks the live instance over HTTP.

**Gating decision:** Report-only (`fail_action: false`). DAST tends to be noisier than SAST/SCA; running it report-only first is standard practice before committing to a gate.

**Friction encountered:** `zaproxy/action-baseline`'s bundled artifact-upload client is incompatible with GitHub's current Artifacts API backend, causing a `400 Bad Request: artifact name is not valid` error regardless of the artifact name used — a known upstream bug, not a configuration issue. Worked around with `continue-on-error: true` on the ZAP step plus a separate, explicit `actions/upload-artifact@v4` step to capture the report reliably.

**Real finding — Missing CSP Header (Medium, systemic across all tested URLs):** The application never sets a `Content-Security-Policy` header at the middleware level. Doesn't cause harm on its own, but removes a key mitigation against XSS — if any injection vulnerability exists elsewhere (see the CodeQL finding above), CSP would normally limit its blast radius; its absence removes that backstop entirely.

### What This Demonstrates
- Understanding what each scanning category can and can't detect (static code vs. dependency metadata vs. runtime behavior)
- A deliberate, stated gating philosophy rather than uniform blocking
- Debugging real CI tooling bugs (permissions errors, an upstream artifact-upload incompatibility) rather than following a tutorial blind
- Triaging findings with security reasoning — severity, exploitability, blast radius — not just "found X issues"

---

## Project 5 — Automation / Triage / Reporting

Built directly on Project 1's output to convert raw scan noise into an actionable, low-noise workflow.

### 1. Fetch — `fetch_findings.py`

**Before:** Findings only existed as something a human had to manually browse in the GitHub Security tab or an HTML report — no structured, scriptable access.

**Approach:** Pulls CodeQL alerts via GitHub's Code Scanning Alerts REST API (paginated, so results aren't silently truncated past 100), normalizes each into the fields actually needed downstream — severity, rule ID, file/line, state, URL — and saves as clean JSON.

**Design decision:** Used the processed Alerts API rather than parsing raw SARIF directly — faster to a working end-to-end pipeline, with raw SARIF parsing left as a natural extension if Snyk/ZAP outputs are added later.

### 2. Prioritize — `prioritize.py`

**Before:** 91 raw findings, many of which were repeated instances of the same underlying issue — no structured way to see the real signal.

**Approach:** Groups findings by `rule_id` (the actual issue *type*, not the individual alert), sorts by severity then occurrence count.

**Real result:** 91 raw alerts collapsed to **24 distinct issue types**. The single largest group — `js/missing-rate-limiting`, 32 occurrences in `server.ts` — is really **one architectural gap** (no global rate-limiting middleware), not 32 separate bugs to triage individually. This is the concrete case for why dedup-before-triage matters: without it, a third of all findings would individually distract from the fact that they share one root cause and one fix.

### 3. Auto-issue creation — `create_issues.py`

**Before:** Even after prioritization, criticals still required a human to manually open GitHub Issues for tracking.

**Approach:** Creates one GitHub Issue per **critical rule group** (not per raw finding), with the issue body listing every affected file/line so no location is lost despite the consolidation.

**Friction encountered:** Initial duplicate-detection logic filtered existing issues by GitHub label (`security-automated`) before comparing titles — but if a label failed to attach cleanly on creation, the lookup silently returned nothing, and re-running the script created duplicate issues. Fixed by abandoning the label pre-filter entirely: now fetches *all* open issues and matches by `rule_id` parsed directly from the issue body, which is more robust and independent of label-attachment success. Added a debug print of exactly which rule_ids were found already-open, making the detection logic's behavior visible rather than a silent black box.

**Design decision:** Scoped to critical severity only, deliberately — keeps the Issues tab meaningful rather than spammed with the same 24 issue types (including 70 high-severity instances) every run.

### 4. Dashboards — `dashboard.py` (Streamlit) and `grafana/` (Docker Compose)

**Before:** The prioritized JSON report existed, but still required manually opening and reading a file to understand the findings landscape.

**Two implementations, deliberately:**
- **Streamlit** — fast, scriptable, pure Python; reads the JSON directly, no separate infrastructure
- **Grafana** — closer to a production observability pattern: a lightweight file server exposes the findings JSON over HTTP, Grafana's Infinity plugin queries it, and the **datasource itself is provisioned as code** (`infinity.yml`, auto-loaded on container start) rather than configured by clicking through the UI — reproducible from a fresh `docker compose up` with zero manual steps

**Friction encountered:** Adding a query panel initially crashed with a React error. Root cause: the Infinity plugin's latest auto-installed release requires Grafana 11.6+, but the Grafana image was pinned to 11.1.0 — a version mismatch between the core platform and a plugin, structurally the same category of problem the pipeline is built to catch in *application* dependencies, just surfacing in the tooling stack instead. Fixed by bumping the Grafana image version.

### What This Demonstrates
- Turning raw, high-volume scanner output into something a human can actually act on
- Idempotent automation — safe to rerun without creating duplicate work, and debugged when it initially wasn't
- Range across tooling philosophies: a fast scriptable dashboard vs. a provisioned-as-code observability setup
- Diagnosing failures methodically (label-filter bug, plugin/platform version mismatch) with visible debug output rather than guesswork


	---

	## Project 2 — Pipeline Hardening & Supply Chain Security

	Where Project 1 scans the *application* for vulnerabilities, Project 2 hardens the *pipeline itself* — the CI/CD infrastructure that runs those scans is a supply-chain target in its own right, and needs the same scrutiny.

	### 1. Pinning GitHub Actions to Commit SHA

	**Before:** All `uses:` references were pinned to mutable version tags (`actions/checkout@v4`, `snyk/actions/node@master`).

	**Risk:** Version tags can be moved to point at a different commit at any time — by the maintainer, or by an attacker who compromises the maintainer's account. `snyk/actions/node@master` was the worst case: pinned to a branch that moves on *every* commit, with zero version stability. This is the same attack class behind real supply-chain incidents like the `tj-actions/changed-files` compromise.

	**After:** Every action is pinned to its full 40-character commit SHA, with a version-tag comment for readability:
	```yaml
	- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
	- uses: snyk/actions/node@9adf32b1121593767fc3c057af55b55db032dc04 # v1.0.0
	```
	SHAs were resolved via `git ls-remote <repo> refs/tags/*` rather than trusted from any third-party source, since an incorrect SHA silently breaks the pipeline (unlike an incorrect tag, which resolves to a valid-but-wrong version).

	**Branch protection:** `master` now requires PRs (no direct pushes) and passing status checks from all four pipeline jobs before merge — making the pipeline load-bearing rather than advisory.

	### 2. SBOM Generation

	**Tool choice:** Syft (`anchore/sbom-action`), not the npm-based `cyclonedx-npm` tool. Notably, during Day 1-2's Snyk scan, `@cyclonedx/cyclonedx-npm@4.2.1` itself was flagged with a High-severity Command Injection vulnerability — a reminder that supply-chain tooling has its own supply chain. Syft runs as an external Go binary and never becomes a project dependency, avoiding that risk entirely.

	**Format:** CycloneDX JSON — a machine-readable, standardized inventory of every dependency and version in the app, enabling instant "am I affected by this new CVE?" lookups without a fresh scan.

	**Friction encountered:** The first SBOM run picked up GitHub Actions references from Juice Shop's original upstream workflow files (Syft's Actions cataloger scans all `.github/workflows/*.yml`, not just `security.yml`), producing duplicate/irrelevant entries. Scoped Syft to exclude `.github/` via `SYFT_EXCLUDE` to keep the SBOM focused on application dependencies — though CI supply-chain visibility is itself a legitimate SBOM use case worth revisiting as a separate artifact.

	**Cross-validation:** SBOM component count checked against Snyk's reported dependency count (814) as a sanity check that both tools see a consistent dependency tree.

	### 3. Artifact Signing with cosign (Sigstore)

	**Approach:** Keyless signing — no long-lived private key to generate, rotate, or leak. GitHub Actions' OIDC identity token is exchanged for a short-lived signing certificate from Sigstore's Fulcio CA, and the signing event is permanently recorded in Sigstore's public Rekor transparency log.

	**What's signed:** The SBOM artifact (`sbom.cyclonedx.json`), producing a `.sig` signature and `.crt` ephemeral certificate.

	**Verification (the actual point):**
	```bash
	cosign verify-blob \
	  --signature sbom.cyclonedx.json.sig \
	  --certificate sbom.cyclonedx.json.crt \
	  --certificate-identity-regexp "https://github.com/ezio143/juice-shop/.github/workflows/security.yml@.*" \
	  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
	  sbom.cyclonedx.json
	```
	This lets anyone — not just someone who trusts this repo by default — cryptographically confirm the SBOM was produced by *this specific workflow, in this specific repo*, and hasn't been altered since. The `--certificate-identity-regexp` check is what makes this meaningful: without it, a signature from any GitHub Actions pipeline would pass verification, not just this one.

	### What This Demonstrates
	- Understanding that CI/CD pipelines are themselves supply-chain attack surface, not just a delivery mechanism for scanning the app
	- Practical SHA-pinning workflow (resolving and verifying SHAs directly from source, not trusting copy-pasted values)
	- SBOM generation with deliberate tool selection reasoning (avoiding a tool with its own known vulnerability)
	- Keyless artifact signing and — critically — actual local verification, not just "the signing step ran"
	- Documenting real friction (the `.github/` scope leak, the tooling vulnerability) rather than presenting a frictionless narrative