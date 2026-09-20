FROM python:3.12-slim

# Pinned tool versions. Unpinned installs make the image non-reproducible and
# let an upstream release change scan results without a DockSec change.
ARG TRIVY_VERSION=0.74.0
ARG HADOLINT_VERSION=2.15.1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Hadolint.
# -f is required: without it curl exits 0 on an HTTP error and writes the error
# page to the destination, producing a "successful" build with a text file where
# the binary should be.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) hadolint_arch='x86_64' ;; \
        arm64) hadolint_arch='arm64' ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/hadolint \
        "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${hadolint_arch}"; \
    chmod +x /usr/local/bin/hadolint

# Install Trivy from the release tarball rather than the install script, so the
# download is version-addressed and a redirect or a moved script cannot silently
# change what lands in the image.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) trivy_arch='Linux-64bit' ;; \
        arm64) trivy_arch='Linux-ARM64' ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${trivy_arch}.tar.gz"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm -f /tmp/trivy.tar.gz

# Fail the build if either tool is missing or not executable. The previous
# install steps could fail silently, shipping an image whose every scan errored
# with "Missing required tools: trivy".
RUN trivy --version && hadolint --version

# Build and install from a dedicated directory. /github/workspace is where the
# Action mounts the user's repository, so installing there both shipped the
# DockSec source to every user and left files that a bind mount then shadowed.
WORKDIR /src
COPY . .

# Install DockSec with the AI extra: the image backs the GitHub Action, which
# exposes AI analysis inputs, so a scan-only install would make those inputs fail.
RUN pip install --no-cache-dir ".[ai]"

# Fail the build if the CLI itself is not importable and runnable.
RUN docksec --version

# The Action mounts the repository being scanned here; it must start empty.
# Leaving /src first so the build sources can be removed rather than left behind.
WORKDIR /github/workspace
RUN rm -rf /src

# Copy and set permissions for entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
