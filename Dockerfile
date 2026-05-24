FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (static binary for maximum compatibility)
RUN arch=$(uname -m) && \
    if [ "$arch" = "arm64" ] || [ "$arch" = "aarch64" ]; then DOCKER_ARCH="aarch64"; else DOCKER_ARCH="x86_64"; fi && \
    curl -fsSL "https://download.docker.com/linux/static/stable/$DOCKER_ARCH/docker-26.1.1.tgz" | tar -xzC /tmp && \
    mv /tmp/docker/docker /usr/local/bin/ && \
    rm -rf /tmp/docker

# Install Hadolint
RUN arch=$(uname -m) && \
    if [ "$arch" = "x86_64" ]; then HADOLINT_ARCH="x86_64"; else HADOLINT_ARCH="arm64"; fi && \
    curl -sL -o /usr/local/bin/hadolint "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-$HADOLINT_ARCH" && \
    chmod +x /usr/local/bin/hadolint

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /github/workspace

# Copy the project files
COPY . .

# Install DockSec and its dependencies
RUN pip install --no-cache-dir .

# Copy entrypoint scripts
COPY entrypoint.sh /entrypoint.sh
COPY docker-runner.sh /docker-runner.sh
RUN chmod +x /entrypoint.sh /docker-runner.sh

# Create scan and results directory with open permissions
RUN mkdir -p /scan/results && chmod -R 777 /scan

# Set default entrypoint for GitHub Actions
ENTRYPOINT ["/entrypoint.sh"]

# Default CMD (can be overridden)
CMD ["--help"]
