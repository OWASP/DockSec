FROM python:3.12-slim

# --- Build arguments ---
ARG DOCKER_GID=999
ARG DOCKER_UID=10001
ARG DOCKER_USER_GID=10001

# --- System dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        ca-certificates \
        gosu \
    && rm -rf /var/lib/apt/lists/*

# --- Docker CLI (GPG-signed APT repository) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/* \
    && docker --version

# --- Linter install (pinned) ---
ARG HADOLINT_VERSION=2.15.1
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

# --- Scanner install (pinned) ---
ARG TRIVY_VERSION=0.74.0
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

# Fail the build if any tool is missing
RUN trivy --version && hadolint --version && docker --version

# --- Build and install DockSec ---
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir ".[ai]"
RUN docksec --version

# Prepare workspace and clean build sources
WORKDIR /github/workspace
RUN rm -rf /src

# --- Non-root user ---
RUN groupadd -g ${DOCKER_USER_GID} docksec && \
    useradd -m -u ${DOCKER_UID} -g docksec -s /sbin/nologin -c "DockSec App User" docksec

# --- Docker socket group (host GID match) ---
RUN if getent group ${DOCKER_GID} >/dev/null; then \
        existing=$(getent group ${DOCKER_GID} | cut -d: -f1); \
        usermod -aG "$existing" docksec; \
    else \
        groupadd -g ${DOCKER_GID} docker_host && \
        usermod -aG docker_host docksec; \
    fi

# --- DockSec results directory with correct ownership ---
RUN mkdir -p /home/docksec/.docksec/results && \
    chown -R docksec:docksec /home/docksec/.docksec

# Bake HOME and DOCKSEC_RESULTS_DIR into the image so the non-root CLI
# always resolves to a writable directory, regardless of how privileges
# are dropped by the entrypoint. Users can still override with
# `docker run -e DOCKSEC_RESULTS_DIR=...`.
ENV HOME=/home/docksec \
    DOCKSEC_RESULTS_DIR=/home/docksec/.docksec/results

# --- Entrypoint ---
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    chown docksec:docksec /entrypoint.sh && \
    chown -R docksec:docksec /github/workspace

ENTRYPOINT ["/entrypoint.sh"]
