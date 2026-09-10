# KODA offline scanner image for closed-network Linux x86_64 servers.
# Multi-stage: the source offline tarball and install intermediates never
# reach a runtime layer. Build via platforms/linux/package-docker-offline.sh,
# which pins PYTHON_IMAGE to a digest and injects OCI labels.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS installer

ARG KODA_BUNDLE
COPY ${KODA_BUNDLE} /tmp/koda-bundle.tar.gz

# Reuse the existing offline installer: it verifies manifest.sha256, copies
# tools/vuln-data, imports the Grype DB, and unpacks the Playwright wheels.
RUN mkdir -p /tmp/koda-bundle \
 && tar -xzf /tmp/koda-bundle.tar.gz -C /tmp/koda-bundle --strip-components=1 \
 && KODA_PREFIX=/opt/koda bash /tmp/koda-bundle/install.sh --no-link \
 && mv /opt/koda/manifest.sha256 /opt/koda/source-bundle-manifest.sha256 \
 && rm -rf /opt/koda/app/render-wheels \
      /opt/koda/grype-db/incoming \
      /tmp/koda-bundle /tmp/koda-bundle.tar.gz \
 && chmod -R a+rX /opt/koda

FROM ${PYTHON_IMAGE} AS runtime

COPY --from=installer /opt/koda /opt/koda

# Chromium shared-library dependencies for dashboard PDF export, then a
# the SSH client for scheduled collection, then a fixed non-root user.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && PYTHONPATH=/opt/koda/render-lib python3 -m playwright install-deps chromium \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 1000 koda \
 && useradd --uid 1000 --gid 1000 --home-dir /home/koda --create-home koda

ENV KODA_PREFIX=/opt/koda \
    KODA_GRYPE_BIN=/opt/koda/tools/grype \
    HOME=/tmp/koda-home \
    XDG_CACHE_HOME=/tmp/koda-cache \
    GRYPE_DB_CACHE_DIR=/opt/koda/grype-db/db \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_VALIDATE_AGE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false

WORKDIR /work
USER 1000:1000

ENTRYPOINT ["/opt/koda/bin/koda"]
CMD ["--help"]
