#!/bin/bash
set -e

# Set environment variables from inputs.
# Only export values that were actually provided: exporting an empty string is
# not the same as leaving a variable unset. An empty LLM_PROVIDER fails
# DocksecConfig validation and aborts the run with a traceback, even in
# --scan-only mode where no provider is needed at all.
for var in OPENAI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY LLM_PROVIDER LLM_MODEL; do
  input_var="INPUT_${var}"
  if [ -n "${!input_var}" ]; then
    export "${var}=${!input_var}"
  fi
done

# Run DockSec
# The inputs are passed as environment variables prefixed with INPUT_
# e.g., inputs.dockerfile becomes INPUT_DOCKERFILE

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

printf 'Running: docksec'; printf ' %q' "${ARGS[@]}"; printf '\n'
docksec "${ARGS[@]}"
