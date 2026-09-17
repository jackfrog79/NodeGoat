# jas-samples/

This directory is **not part of the NodeGoat application** — none of it is imported,
compiled into, or served by the app. It exists purely as fixture code for the
**JFrog Advanced Security (JAS)** golden demo described in the top-level
[README.md](../README.md), so that scan categories the JS-only NodeGoat app can't
naturally exercise (non-JS SAST languages, IaC, Services/Applications misconfig,
Secrets) still have real, scannable material in the repo.

Every vulnerable pattern here is intentional and documented with a comment
explaining the CWE/OWASP category it demonstrates — same convention as
NodeGoat's own `app/routes` and `app/data` files. Nothing in this directory is
built, run, or deployed; secrets are inert/fake.

| Subfolder | JAS pillar | Notes |
|---|---|---|
| `sast/<language>/` | SAST | One file per non-JS language in JFrog's SAST rule set, plus one JS file for the two categories NodeGoat's real routes don't already cover |
| `iac/terraform/` | Misconfiguration Scans → IaC | AWS / Azure / GCP modules with intentional misconfigurations |
| `services/` | Misconfiguration Scans → Services | NGINX + Prometheus configs with insecure defaults, wired into a standalone compose overlay |
| `secrets/` | Secrets Detection | Fake, non-functional credentials covering each detector category |

See the top-level README for the full pillar-by-pillar mapping and severity table.
