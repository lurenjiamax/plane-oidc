#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export HTTP_PROXY="${HTTP_PROXY:-http://100.64.0.59:7890}"
export HTTPS_PROXY="${HTTPS_PROXY:-http://100.64.0.59:7890}"
tag="${PLANE_IMAGE_TAG:-oidc-1.3.1-local}"
docker build --network=host --build-arg HTTP_PROXY --build-arg HTTPS_PROXY \
  -f apps/api/Dockerfile.oidc -t "lurenjiamax/plane-backend:$tag" apps/api
for app in web admin; do
  docker build --network=host --build-arg HTTP_PROXY --build-arg HTTPS_PROXY \
    --build-arg NODE_OPTIONS=--max-old-space-size=4096 \
    -f "apps/$app/Dockerfile.$app" -t "lurenjiamax/plane-$app:$tag" .
done
