#!/bin/bash
set -e

# Set environment variables from inputs
export OPENAI_API_KEY="${INPUT_OPENAI_API_KEY}"
export ANTHROPIC_API_KEY="${INPUT_ANTHROPIC_API_KEY}"
export GOOGLE_API_KEY="${INPUT_GOOGLE_API_KEY}"
export LLM_PROVIDER="${INPUT_LLM_PROVIDER}"
export LLM_MODEL="${INPUT_LLM_MODEL}"

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
