#!/usr/bin/env bash
# Run the Mudek pytest suite inside the api container.
#
# Usage:
#   ./scripts/run_tests.sh              # run all tests
#   ./scripts/run_tests.sh -k letter    # run matching tests only
set -euo pipefail

CONTAINER="${CONTAINER:-mudek_api}"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "Container '${CONTAINER}' is not running. Start it with: docker compose up -d"
  exit 1
fi

# Install pytest into the running container if missing (idempotent).
docker exec "${CONTAINER}" python -c "import pytest" 2>/dev/null || {
  echo "Installing pytest inside ${CONTAINER}..."
  docker exec "${CONTAINER}" pip install --no-cache-dir pytest pytest-asyncio
}

exec docker exec -e SECRET_KEY="${SECRET_KEY:-test-secret-not-production-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}" \
  "${CONTAINER}" python -m pytest -v /app/tests/ "$@"
