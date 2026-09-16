# NodeGoat — JFrog Advanced Security Golden Demo

NodeGoat is [OWASP's](https://github.com/OWASP/NodeGoat) intentionally
vulnerable Node.js training app for the OWASP Top 10. This fork extends it
into a **golden demo for JFrog Advanced Security (JAS)**: every JAS scan
category has real, scannable material in this repo, and this README maps
each finding to the exact file and line that produces it.

JAS is five things, all covered below:

1. [SAST](#1-sast-static-application-security-testing)
2. [Secrets Detection](#2-secrets-detection)
3. [Contextual Analysis of CVEs](#3-contextual-analysis-of-cves)
4. [Misconfigurations Scans](#4-misconfigurations-scans) (IaC / Services / Applications)
5. [GitHub Actions Workflow Scanner: Pwn-Request Detection](#5-github-actions-workflow-scanner-pwn-request-detection)

Nothing under `jas-samples/` is compiled, imported, or deployed by the real
app — it's fixture code for languages/scan types the JS-only app can't
otherwise exercise. Everything under `app/`, `config/`, and `server.js` **is**
the real, running application, and its vulnerabilities are genuine (and, per
NodeGoat tradition, commented with the fix).

---

## 1. SAST (Static Application Security Testing)

JFrog's SAST rules map to CWE and OWASP Top 10 (2021) across C/C++, C#, Go,
Java, JavaScript, Kotlin, PHP, Python, and Rust, grouped roughly as:
Injection-class (High), Access/crypto issues (Medium), Info exposure
(Low/Medium), and language-specific extras (Python AI/agent risk rules,
Kotlin Android rules).

**Already in the real app (no fixture needed):**

| File | Finding | Category | Severity |
|---|---|---|---|
| `app/routes/report-export.js:13` | `eval(req.body.formula)` | Code injection (CWE-95) | High |
| `app/routes/report-export.js:19` | `exec()` built from `req.query.reportName` | Command injection (CWE-78) | High |
| `app/routes/report-export.js:28-29` | `path.join` on unsanitized `req.query.file` | Path traversal (CWE-22) | Medium |
| `app/routes/report-export.js:44` | `req.query.owner` concatenated into HTML response | Reflected XSS (CWE-79) | High |
| `app/routes/report-export.js:39` | `crypto.createCipher("des-ecb", "static-export-key")` | Weak crypto algorithm + hardcoded key (CWE-327 / CWE-798) | Medium |
| `config/env/all.js:8-9` | `cookieSecret` / `cryptoKey` literals | Hardcoded credentials (CWE-798) | Low/Medium |
| `app/routes/session.js:16-17`, `app/data/user-dao.js:51-53` | `Math.random()` for allocations/date fuzzing | Insecure randomness (CWE-338) | Medium |

`app/routes/report-export.js` is deliberately **not wired into `server.js`**
— the patterns are real enough for static analysis to flag, without opening
a live RCE endpoint on a demo host.

**Added as fixtures for the languages the app can't otherwise cover**
(`jas-samples/sast/`, none built or executed):

| Path | Language | Findings | Category | Severity |
|---|---|---|---|---|
| `sast/c/vuln.c` | C | `system()` command injection; `rand()` weak randomness | Injection (High) / Insecure random (Medium) |
| `sast/cpp/vuln.cpp` | C++ | String-concat SQL injection; hardcoded DB password | Injection (High) / Hardcoded creds (Low-Med) |
| `sast/csharp/Vuln.cs` | C# | `SqlCommand` string-concat SQLi; `BinaryFormatter` deserialization | Injection (High) / Insecure deserialization (Medium) |
| `sast/go/vuln.go` | Go | `exec.Command` via shell; SSRF via unchecked `http.Get`; MD5 password hash | Injection (High) / SSRF (Medium) / Weak crypto (Medium) |
| `sast/java/Vuln.java` | Java | XXE via default `DocumentBuilderFactory`; `ObjectInputStream` deserialization; hardcoded credential | XXE (Medium) / Insecure deserialization (High) / Hardcoded creds (Low-Med) |
| `sast/javascript/extra-vuln.js` | JavaScript | ReDoS-prone regex; unchecked open redirect | ReDoS (Medium) / Open redirect (Low-Med) |
| `sast/kotlin/VulnActivity.kt` + `AndroidManifest.xml` | Kotlin | Exported `Activity` with no permission; mutable implicit `PendingIntent` | Android component exposure (Medium-High) |
| `sast/php/vuln.php` | PHP | LDAP filter injection; `mysqli` string-concat SQLi | Injection (Medium/High) |
| `sast/python/vuln.py` | Python | SSRF via unchecked `requests.get`; Jinja2 SSTI via `render_template_string`; **prompt-injection-rce** (`subprocess.run(llm_output, shell=True)`); hardcoded API key | SSRF (Medium) / SSTI (High) / AI-agent risk (High) / Hardcoded creds (Low-Med) |
| `sast/rust/vuln.rs` | Rust | `serde_json` deserialization of untrusted bytes into a privilege-bearing struct; hardcoded token | Insecure deserialization (Medium) / Hardcoded creds (Low-Med) |

The Python file exists specifically to exercise JFrog's AI/agent-risk rule
family (prompt-injection-rce, Jinja2 injection) alongside the classic OWASP
categories — the "language-specific extras" called out in JFrog's SAST
coverage.

---

## 2. Secrets Detection

JFrog Secrets Detection covers Access Tokens/Keys, Certificate & Private Key
Detection, High Entropy Textual Secrets, and URL Secrets Detection, plus
**Token Validation** — actually checking whether a discovered secret is live.

`jas-samples/secrets/leaked-credentials.env` contains one **fake,
non-functional** example of each category (fake AWS key pair, a fake GitHub
PAT, a fake RSA private key block, a high-entropy internal API key, and a
database URL with embedded credentials). Because none of these were ever
real, Token Validation should correctly report them all as inactive — which
is itself worth showing: a scanner that only pattern-matches would treat a
dead AWS key the same as a live one; Token Validation is what tells a
responder which finding to drop everything for.

---

## 3. Contextual Analysis of CVEs

This isn't a separate scan — it sits on top of SCA (dependency CVE
scanning) and determines whether a known CVE in a dependency is *actually
exploitable* in your specific code/environment, cutting false positives.

NodeGoat's real `package.json` is the natural substrate here: it deliberately
pins ancient, CVE-laden versions (`lodash@4.17.4`, `mongodb@2.1.18`,
`marked@0.3.5`, `swig@1.4.2`, `needle@2.2.4`, `forever@2.0.0`) as part of the
OWASP A9 ("Using Components with Known Vulnerabilities") lesson — no new
fixtures needed; point Xray's SCA + Contextual Analysis at this repo as-is.

Key facts (from JFrog's docs, not guessed):

- Roughly **a third of JFrog's contextual-analysis scanners don't rely on
  code reachability at all** — for many CVEs, exploitability depends on
  config files, CLI flags, or host properties invisible to code scanning.
  JFrog's own example: **CVE-2024-27316** (Apache HTTP/2 memory-exhaustion
  DoS) is only exploitable when HTTP/2 is enabled via `LoadModule
  http2_module` in `httpd.conf` — Apache exposes no API for this, so no
  amount of source or binary reachability analysis can determine
  exploitability; only config-aware analysis can.
- Coverage spans source code and compiled binaries, including **Docker/OCI
  images** and **Uber/Fat JARs**, plus Rust binaries (Xray 3.79.x+) and .NET
  binaries (Xray 3.95.4+).
- The **Transitive Dependency** feature extends this to CVEs introduced via
  dependencies-of-dependencies, with a visual call graph, direct-vs-indirect
  exploitation labeling, and exportable file/line evidence.

---

## 4. Misconfigurations Scans

Three distinct sub-scans, not one:

### IaC Scans

Terraform Modules/Plan files pre-deployment, and Terraform State files (in
Artifactory) post-deployment, across AWS/Azure/GCP.

| Path | Cloud | Findings |
|---|---|---|
| `jas-samples/iac/terraform/aws/main.tf` | AWS | Public-read S3 bucket + disabled public-access-block; security group open on all ports to `0.0.0.0/0`; wildcard `"*:*"` IAM policy; hardcoded RDS password; `storage_encrypted = false`; disabled CloudTrail logging |
| `jas-samples/iac/terraform/azure/main.tf` | Azure | Public blob access on a storage account; `TLS1_0` minimum; NSG rule allowing any source/port |
| `jas-samples/iac/terraform/gcp/main.tf` | GCP | `allUsers`-readable GCS bucket; firewall rule open to `0.0.0.0/0` on all protocols; primitive `roles/owner` bound to a service account |

### Services Scans

Checks common OSS services running **inside containers** — currently Envoy,
Etcd, Prometheus, NGINX, Apache — for insecure defaults.

| Path | Service | Findings |
|---|---|---|
| `jas-samples/services/nginx/nginx.conf` | NGINX | No HTTPS redirect (plaintext-only `listen 80`); `TLSv1`/`TLSv1.1` + weak cipher suite; unauthenticated `/nginx_status` admin endpoint |
| `jas-samples/services/prometheus/prometheus.yml` | Prometheus | Admin/lifecycle API enabled with no auth; scrape-target basic-auth password stored in plaintext |

Both are wired into `jas-samples/services/docker-compose.services-demo.yml`
— a **standalone overlay**, intentionally separate from the app's real
`docker-compose.yml`, so these misconfigs never affect the actual running
app. Run it in isolation with:
```
docker compose -f jas-samples/services/docker-compose.services-demo.yml up
```

### Applications Scans

Checks library/service usage inside containers for **Python and Node.js**
specifically. NodeGoat's own container already provides real Node.js
findings:

| File | Finding |
|---|---|
| `app/routes/report-export.js:39` | Insecure key storage / weak crypto key (`des-ecb`, hardcoded key) |
| `app/routes/session.js:53` (`handleLoginRequest`) | No rate limiting/lockout — insufficient brute-force throttling on login |
| `app/routes/report-export.js:19` | Unsafe `exec()` with user-controlled input |

> **Note:** for Helm/Helm OCI charts, Services and Applications findings come
> from the container images the chart deploys, not the chart's own YAML —
> not applicable to this repo (no Helm chart here), but worth remembering if
> you extend this demo with one.

---

## 5. GitHub Actions Workflow Scanner: Pwn-Request Detection

A fifth, CI/CD-specific check under Advanced Security, available via
Frogbot v3.6.0+. It performs static analysis on `.github/workflows/*.yml`
and flags a workflow when **all three** conditions hold:

1. It's triggered on `pull_request_target` (which runs with the base repo's
   privileges and secrets, even for a PR from a fork).
2. A step using `actions/checkout` sets `ref` to the PR head
   (`github.event.pull_request.head.sha`, `github.head_ref`, or a
   `refs/pull/.../merge` ref) — i.e. it checks out and effectively executes
   the fork's code inside that privileged context.
3. There's no mitigation: no condition restricting execution to non-fork PRs,
   and no restriction to trusted actors (e.g. `dependabot`/`renovate`).

The risk: an attacker opens a PR from a fork with malicious code; it runs
inside the workflow's privileged context, exposing secrets (API keys, etc.)
and, if the workflow has write permissions, potentially letting the attacker
push to the repo.

`.github/workflows/jas-demo-pwn-request.yml` reproduces exactly this shape
for the scanner to catch — and nothing else: `permissions: contents: read`
only, no secrets referenced anywhere in the job, and the only post-checkout
step is a no-op `echo`. The vulnerable *pattern* is what's being
demonstrated; there is nothing sensitive in this workflow to actually
exploit.

---

## Getting Started

### Know it!

This application bundles a tutorial page that explains the OWASP Top 10
vulnerabilities and how to fix them, at
[http://localhost:4000/tutorial](http://localhost:4000/tutorial) once running.

##### Default user accounts

The database comes pre-populated with these seeded accounts:
* Admin Account - u:`admin` p:`Admin_123`
* User Accounts (u:`user1` p:`User1_123`), (u:`user2` p:`User2_123`)
* New users can also be added using the sign-up page.

### How to Set Up Your Copy of NodeGoat

#### OPTION 1 — Run on your machine

1. Install [Node.js](http://nodejs.org/) (NodeGoat requires Node v8+).
2. `git clone` this repo and `cd` into it.
3. `npm install`
4. Set up MongoDB (local `mongod`, or a remote instance — set `MONGODB_URI`).
5. `npm run db:seed`
6. `npm start` (http://localhost:4000/) or `npm run dev` for auto-restart
   (http://localhost:5000/).

By default the app listens on port 4000 and connects to
`mongodb://localhost:27017`. Override with the `PORT` and `MONGODB_URI` env
vars; other settings live in `config/env/all.js`.

#### OPTION 2 — Run on Docker

```
docker-compose build
docker-compose up
```
This uses the repo's `Dockerfile`/`docker-compose.yml` (unrelated to the
`jas-samples/services/docker-compose.services-demo.yml` overlay above, which
is JAS-fixture-only).

#### OPTION 3 — Deploy to Heroku

See the original [OWASP/NodeGoat instructions](https://github.com/OWASP/NodeGoat#option-3---deploy-to-heroku) — a free MongoDB Atlas cluster plus the Heroku deploy button.

### Build & Scan (CI)

| Workflow | Purpose |
|---|---|
| `.github/workflows/build.yml` | Installs deps, seeds Mongo, boots the app, and smoke-tests it on every push/PR — real green/red build history for this repo. A second, best-effort stage re-installs via `jf npm install` and publishes build-info to Artifactory (`nodegoat-golden-jas-demo` build, `jackcu` project), then triggers an Xray build-scan so this build shows up in Xray's Builds list. |
| `.github/workflows/frogbot-scan-repository.yml` | Full Frogbot/Xray scan on push to `master`. |
| `.github/workflows/frogbot-scan-pr.yml` | Frogbot/Xray scan on pull requests. |
| `.github/workflows/jas-demo-pwn-request.yml` | The intentionally-vulnerable-pattern workflow described in [§5](#5-github-actions-workflow-scanner-pwn-request-detection). |

---

## Sources

- [Contextual Analysis of CVEs](https://docs.jfrog.com/security/docs/contextual-analysis-of-cves-1) — JFrog docs
- [Misconfigurations Scans](https://docs.jfrog.com/security/docs/misconfigurations-scans) — JFrog docs
- [GitHub Actions Workflow Scanner: Pwn-Request Detection](https://docs.jfrog.com/security/docs/github-actions-workflow-scanner-pwn-request-detection) — JFrog docs
- [CVE-2022-23943 — Apache httpd memory corruption deeper analysis](https://jfrog.com/blog/diving-into-cve-2022-23943-a-new-apache-memory-corruption-vulnerability/) — JFrog Security Research
- [How JFrog's AI-Research Bot Found OSS CI/CD Vulnerabilities to Prevent Shai Hulud 3.0](https://jfrog.com/blog/jfrog-ai-bot-stopped-shai-hulud-3/) — JFrog Security Research

## Report bugs, Feedback, Comments

Open a new [issue](https://github.com/OWASP/NodeGoat/issues) on the upstream
project or contact the team via [Slack](https://owasp.slack.com/messages/project-nodegoat/) or [Gitter](https://gitter.im/OWASP/NodeGoat).

## Contributing

Please follow [the contributing guide](CONTRIBUTING.md).

## Code Of Conduct (CoC)

This project is bound by a [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributors

Upstream [OWASP/NodeGoat contributors](https://github.com/OWASP/NodeGoat/graphs/contributors).

## License

Code licensed under the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).
