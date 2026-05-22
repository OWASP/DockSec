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

if [ -n "${INPUT_OUTPUT}" ]; then
  ARGS+=("-o" "${INPUT_OUTPUT}")
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
