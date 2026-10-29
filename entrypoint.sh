#!/bin/bash
set -e

# ---------------------------------------------------------------------------
# Privilege dropping (non-root hardening)
# ---------------------------------------------------------------------------
# GitHub Docker container actions MUST run as root to access GITHUB_WORKSPACE.
# For standalone `docker run`, drop to the non-root `docksec` user for
# least-privilege execution. Users can override with `docker run --user`.
#
# Detection:
#   - GITHUB_WORKSPACE is set  -> GitHub Action mode -> stay root
#   - UID != 0                 -> already non-root   -> continue
#   - otherwise                -> standalone         -> drop to docksec
if [ "$(id -u)" = "0" ] && [ -z "${GITHUB_WORKSPACE:-}" ]; then
    echo "Standalone run detected: dropping privileges to 'docksec' user."
    # Ensure a writable HOME for the non-root user so results go to
    # ~/.docksec/results instead of the current working directory.
    export HOME=/home/docksec
    export DOCKSEC_RESULTS_DIR=/home/docksec/.docksec/results
    mkdir -p "$DOCKSEC_RESULTS_DIR"
    chown -R docksec:docksec "$HOME/.docksec"
    exec gosu docksec "$0" "$@"
fi

# ---------------------------------------------------------------------------
# Set environment variables from Action inputs.
# Only export values that were actually provided: exporting an empty string is
# not the same as leaving a variable unset. An empty LLM_PROVIDER fails
# DocksecConfig validation and aborts the run with a traceback, even in
# --scan-only mode where no provider is needed at all.
# ---------------------------------------------------------------------------
for var in OPENAI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY LLM_PROVIDER LLM_MODEL; do
  input_var="INPUT_${var}"
  if [ -n "${!input_var}" ]; then
    export "${var}=${!input_var}"
  fi
done

# ---------------------------------------------------------------------------
# Build the DockSec argument list from Action inputs and CLI args.
# ---------------------------------------------------------------------------
ARGS=()

if [ -n "${INPUT_DOCKERFILE}" ]; then
  ARGS+=("${INPUT_DOCKERFILE}")
fi

if [ -n "${INPUT_IMAGE}" ]; then
  ARGS+=("-i" "${INPUT_IMAGE}")
fi

if [ -n "${INPUT_COMPOSE}" ]; then
  ARGS+=("-c" "${INPUT_COMPOSE}")
fi

# `output` is a deprecated alias for `output_dir` - the standalone -o/--output
# file flag was removed from the CLI, so both inputs now map to --output-dir.
# output_dir takes precedence if both are set.
if [ -n "${INPUT_OUTPUT_DIR}" ]; then
  ARGS+=("--output-dir" "${INPUT_OUTPUT_DIR}")
elif [ -n "${INPUT_OUTPUT}" ]; then
  ARGS+=("--output-dir" "${INPUT_OUTPUT}")
fi

if [ -n "${INPUT_SEVERITY}" ]; then
  ARGS+=("--severity" "${INPUT_SEVERITY}")
fi

if [ -n "${INPUT_FAIL_ON}" ]; then
  ARGS+=("--fail-on" "${INPUT_FAIL_ON}")
fi

if [ -n "${INPUT_FORMAT}" ]; then
  ARGS+=("--format" "${INPUT_FORMAT}")
fi

if [ "${INPUT_SARIF}" = "true" ]; then
  ARGS+=("--sarif")
fi

if [ "${INPUT_AI_ONLY}" = "true" ]; then
  ARGS+=("--ai-only")
fi

if [ "${INPUT_SCAN_ONLY}" = "true" ]; then
  ARGS+=("--scan-only")
fi

if [ "${INPUT_IMAGE_ONLY}" = "true" ]; then
  ARGS+=("--image-only")
fi

# Forward anything given on the command line. Without this the image only
# honours the INPUT_* variables, so `docker run ... --version` and every other
# direct CLI invocation fails with "Dockerfile path is required".
ARGS+=("$@")

# printf runs its format once even for an empty array, so guard the log line:
# otherwise a bare `docksec` is reported as `docksec ''`.
if [ ${#ARGS[@]} -eq 0 ]; then
  printf 'Running: docksec\n'
else
  printf 'Running: docksec'; printf ' %q' "${ARGS[@]}"; printf '\n'
fi
docksec "${ARGS[@]}"
