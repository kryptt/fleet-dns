#!/bin/bash
set -euo pipefail
REGISTRY=registry.hr-home.xyz
APP=fleet-dns
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
IMG=$REGISTRY/$APP:$VERSION
docker buildx build . -t "$IMG"
docker push "$IMG"
echo "Pushed $IMG"
