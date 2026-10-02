# KODA Offline Docker Delivery

> Updated 2026-10-02 against the local source checkout, including changes under
> development. Publishing this documentation does not publish those source changes
> or establish that GitHub main or previously built release images include them.
> Confirm the deployed version and rebuild/validate the matching bundle before
> relying on the checkout behavior described below.

This single bundle runs KODA's JAR/WAR/EAR SBOM and vulnerability workflow on
an air-gapped Linux x86_64 host. Docker Engine must already be installed. The
installer does not modify Docker configuration, host security settings, or the
global `PATH`.

## Additional checkout boundaries

The following changes are under development in the 2026-10-02 checkout. Rebuild
and validate the corresponding bundle before applying them to an existing
installation; publishing the docs does not update its images or wrappers.

- The suite generates `KODA_GATEWAY_PROOF` in its `.env`, preserves existing
  `[A-Za-z0-9_-]` values of 32–128 characters, writes the environment file with
  mode `0600`, and supplies the same secret to the gateway and portal. The portal
  rejects duplicate identity headers and invalid proof and fails closed when
  proof is unconfigured. Do not distribute the secret to browsers.
- Streaming input is capped at 2 GiB per file. Retained inputs plus active upload
  reservations have a default 10 GiB quota (`KODA_PORTAL_UPLOAD_QUOTA_BYTES`).
  Public portal JSON is capped at 1 MiB; internal scheduled API JSON defaults to
  500 MiB (`KODA_JSON_MAX_BYTES`).
- Execution checks `scan.library.create` / `scan.source.create` independently;
  an `all` scan requires both. Input, export, deletion and external publication
  permissions are separate server-side checks from screen visibility.
- NIS-SBOM and comparison CSV quote every cell and prefix formula-like values
  with a tab. CycloneDX/JSON values are unchanged by this display safeguard.
- Java depth, entry, byte, metadata and Syft output limits may produce partial
  artifacts with warnings and exit code `2`. See the
  [Java runbook](../../../docs/security/java-sbom-vulnerability-scan.en.md) for
  exact checkout limits.

Standalone `dashboard start` provides a compatibility listener/status mode.
Loopback binding or an SSH tunnel alone does not provide Tracker identity and
gateway proof for protected portal login; use the integrated suite for users
and production scans. Source inspection does not establish live Docker/nginx
integration, upgrade compatibility, or Chromium execution.

## Bundle contents

```text
koda-docker-offline-x86_64-<version>/
├── install.sh
├── koda-docker.sh
├── README.md
├── image-ref.txt
├── versions.txt
├── manifest.sha256
└── image/
    └── koda-offline-amd64.tar
```

The image includes KODA, Syft, Grype, an imported Grype database, NVD feeds,
CISA KEV data, and Playwright Chromium for PDF rendering. Runtime update checks
are disabled.

## Install

Move `koda-docker-offline-x86_64-<version>.tar.gz` to the target host, verify its
checksum against the value supplied by the connected build machine, then run:

```bash
mkdir -p /home/user0/projects/koda
cd /home/user0/projects/koda
tar -xzf koda-docker-offline-x86_64-<version>.tar.gz
cd koda-docker-offline-x86_64-<version>
bash install.sh --prefix /home/user0/projects/koda
export KODA_CLI=/home/user0/projects/koda/koda-docker
```

`install.sh` verifies the manifest, host architecture, Docker daemon, image
architecture and labels, runs offline smoke tests, and installs the wrapper in
the selected prefix. Reinstalling the same version is safe.

## Scan and verify

```bash
# Combine multiple deployment roots into one inventory, SBOM, and report set.
"$KODA_CLI" jar-scan \
  --target /jeus/domains/domain1/applications \
  --target /jeus/domains/domain2/applications \
  --output-dir /home/user0/projects/koda/reports/java-scan \
  --fail-on high --fail-on-kev

# Compare deployed archives with an approved CycloneDX SBOM.
"$KODA_CLI" sbom-verify \
  --target /jeus/domains/domain1/applications \
  --sbom /home/user0/projects/koda/approved/production-sbom.cdx.json \
  --output-dir /home/user0/projects/koda/reports/sbom-verification \
  --strict-hash --fail-on-version-conflict --fail-on-untracked --fail-on-mismatch

# Run vulnerability analysis and baseline verification together.
"$KODA_CLI" audit \
  --target /jeus/domains/domain1/applications \
  --baseline /home/user0/projects/koda/approved/production-sbom.cdx.json \
  --reports /home/user0/projects/koda/reports/production
```

Exit code `0` means the selected gates passed, `1` means a vulnerability or SBOM
mismatch met a requested gate, and `2` means an input, tool, or runtime error.
Java HTML and Markdown reports are currently generated in Korean; `--language`
accepts only `ko`.

The wrapper automatically mounts `--target`, `--sbom`, and `--baseline-sbom`
paths read-only and mounts `--output-dir` or the parent of `--output` read-write.
Scans run one at a time by default. Set `KODA_ALLOW_CONCURRENT=1` only when the
host can support parallel scan I/O.

## Authenticated Linux portal

Production uses the combined suite at `/koda/`; see
[`../suite/README.ko.md`](../suite/README.ko.md). The suite does not publish port
8765 and reaches KODA only through its private Docker network. Tracker owns the
shared account/session, while KODA keeps its own project roles.

The following standalone mode is for local compatibility testing only.

```bash
"$KODA_CLI" dashboard start --reports /home/user0/projects/koda/reports
"$KODA_CLI" dashboard status
"$KODA_CLI" dashboard logs -f
"$KODA_CLI" dashboard stop
```

The dashboard binds to `127.0.0.1:8765` by default. Use an SSH tunnel for remote
access. Change the host port with `--port` or `KODA_PORT`; expose another bind
address only when that access is explicitly approved.

## Isolation and updates

CLI containers use `--network none`, a read-only root filesystem, a non-root
user, dropped capabilities, `no-new-privileges`, and CPU, memory, PID, and tmpfs
limits. When the wrapper creates its dedicated `koda-dashboard` bridge, it
disables outbound masquerading so the loopback-published port remains reachable
without granting container egress. If a network with that name already exists,
verify its `com.docker.network.bridge.enable_ip_masquerade` option before use
because the wrapper reuses it.

Update by importing a newly built bundle. Keep the previous image tag for
rollback and select it with `KODA_IMAGE=koda-offline:<old-version>` if needed.

- [English documentation index](../../../docs/README.en.md)
- [Korean Docker delivery guide](README.md)
