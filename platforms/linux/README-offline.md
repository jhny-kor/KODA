# KODA Linux Offline Distribution

> Reviewed **2026-10-11**, including the development source in this GitHub publication. Validation covers the x86_64 source installer and actual amd64 container execution; it does not establish a newly packaged/imported complete delivery archive or production deployment. See [validation](../../docs/verification-2026-10-11.md).

This folder is the Linux distribution layer for KODA. It does not fork scanner
logic. Source installs and packages copy the shared Python engine from
`platforms/shared/python/security_scanner/` into the Linux bundle.

## Install From Source

```bash
cd /path/to/koda
bash platforms/linux/install.sh
/home/user0/koda/koda list-categories
```

The offline installer defaults to `/home/user0/koda`. It creates the command
link at `/home/user0/koda/koda`; add `/home/user0/koda` to `PATH` if the short
`koda` command is preferred:

```bash
export PATH=/home/user0/koda:$PATH
koda list-categories
```

Use a custom install location when the server account has a managed application
directory:

```bash
KODA_PREFIX=/srv/koda KODA_BIN_DIR=/usr/local/bin bash platforms/linux/install.sh
```

## Authenticated Linux Portal

For a server-facing UI, use the combined KODA + KODA SBOM Tracker suite. Tracker
owns the account and session; KODA owns independent project roles and
administrator-only rule settings. Both products are served from one HTTPS
origin:

```text
https://<server>/          # KODA SBOM Tracker
https://<server>/koda/     # KODA
```

See [`suite/README.ko.md`](suite/README.ko.md) for the combined air-gapped
archive. Do not publish KODA's port 8765. `koda serve --legacy-dashboard --host
127.0.0.1` remains available only for local compatibility testing.

The installer and package include the Playwright Chromium renderer. Do not omit
Chromium when building an offline bundle: `install.sh` and `package.sh` fail if
the renderer cannot be staged.

## Build An Offline Tarball

Build on a connected machine, then move the tarball into the closed network.

```bash
bash platforms/linux/package.sh
```

For the complete closed-network Java package, build one x86_64 archive from the
connected MacBook:

```bash
KODA_NVD_START_YEAR=2025 \
KODA_NVD_END_YEAR=2026 \
bash platforms/linux/package-offline.sh
```

This includes Syft, Grype, the Grype DB, NVD JSON feeds, and CISA KEV. It
verifies downloaded checksums, and the resulting archive is the only file
that needs to be transferred.

Install on the target Linux server:

```bash
tar -xzf koda-linux-x86_64-0.1.0.tar.gz
cd koda-linux-x86_64-0.1.0
bash install.sh
koda scan --target /deploy/app --format json --output reports/koda.json --fail-on high
```

For the two-page source HTML report, use `--format html`; KODA writes the
requested main file and its `-detail.html` sibling. For Java archives, use
`koda jar-scan --target /deploy/app --format html`; the output contains
`server-library-report.html` and `server-library-report-detail.html`. The
Windows desktop program exposes the same source pair as **HTML (main + detail)**
in its report download menu.

Repeat `--target` to combine multiple deployment roots in one library report.
The shared archive inventory, CycloneDX SBOM, vulnerability aggregation, and
HTML/Markdown outputs cover every supplied root (overlapping files are
deduplicated):

```bash
koda jar-scan \
  --target /deploy/api \
  --target /deploy/worker \
  --output-dir reports/java-scan
```

The archive contains the KODA source, Syft, Grype, Grype DB, selected NVD/CISA
data, Playwright wheels for Python 3.10 through 3.14, and Chromium. The
installer uses only those local files and refuses network installation if an
offline bundle file is missing.

## Deployment Gate

KODA exits with status `1` when `--fail-on` finds a matching severity. Put that
command before deployment promotion:

```bash
koda scan --target "$DEPLOY_DIR" --format json --output reports/koda-security.json --fail-on high
```

For scan plus deployment-shape evidence in one command:

```bash
koda deploy-check --target "$DEPLOY_DIR" --output-dir reports/koda-deploy --fail-on high
```

To verify that the deployed files match an approved shape:

```bash
koda manifest create --target /deploy/package --output reports/approved-manifest.json
koda manifest compare --baseline reports/approved-manifest.json --target /app/current --output reports/manifest-compare.json
```

For a full example, see `examples/deploy-gate.sh`.

## Docker Single Deliverable

For servers that already run Docker Engine, build the closed-network Docker
deliverable instead of a host install:

```bash
bash platforms/linux/package-docker-offline.sh --refresh
```

It reuses `dist/linux/koda-linux-x86_64-<version>.tar.gz` (building it first
when missing), installs it inside a multi-stage `linux/amd64` image with the
Grype DB pre-imported, smoke-tests the image with `--network none`, and emits
`dist/linux/koda-docker-offline-x86_64-<version>.tar.gz` containing the image
tar, `install.sh`, and the `koda-docker` isolation wrapper (network none,
read-only rootfs, non-root, resource limits, ro target / rw report mounts).
See `platforms/linux/docker/README.md` for closed-network installation,
`audit`/`dashboard` usage, rollback, and optional GitLab registry upload.

`package-offline.sh --refresh` re-validates cached yearly NVD feeds against
their `.meta` files; NVD `recent`/`modified` and CISA KEV are re-downloaded on
every build.

## GitLab CI

Use `examples/gitlab-ci.yml` as a starter job. It installs KODA locally in the
job workspace, scans only merge-request changes when a target branch is
available, writes a full HTML report, and writes `reports/koda-host.json` for
the runner host posture.

Set `KODA_DEPLOY_DIR` when the job also has access to a staged deployment
directory and should run `koda deploy-check`.

## Closed-Network Defaults

- Default scans are local and offline.
- Do not enable `--enable-osv` or `--enable-vuln-intel` in a closed network
  unless those services are routed to an approved internal mirror.
- Keep shared scanner changes in `platforms/shared/python/security_scanner/`;
  keep Linux install, packaging, and deployment scripts in `platforms/linux/`.

## Offline Java archive scan

For Linux x86_64 application servers, stage Syft, Grype, and the approved
NVD/CISA KEV files inside the closed network, then run:

~~~bash
koda jar-scan \
  --target /jeus/domains/domain1/applications \
  --output-dir reports/java-scan \
  --syft-bin /opt/koda/tools/syft \
  --grype-bin /opt/koda/tools/grype \
  --nvd-data /opt/koda/vuln-data/nvd \
  --cisa-kev /opt/koda/vuln-data/known_exploited_vulnerabilities.json \
  --fail-on high --fail-on-kev
~~~

Java HTML and Markdown reports are currently generated in Korean; `--language`
accepts only `ko`. Vulnerabilities for the same library and installed version are merged
into one row, and `Final` is the candidate version rechecked against the same
Grype database.

The scanner is read-only, includes nested libraries, and never infers a Maven
version from a filename. Unknown identity, duplicate locations, input
SHA-256, and data-as-of date remain visible in the generated reports. See
docs/security/java-sbom-vulnerability-scan.en.md for the complete runbook.
