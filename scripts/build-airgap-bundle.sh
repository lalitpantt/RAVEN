#!/bin/sh
set -eu
version=${1:-dev}
out=${2:-dist}
go mod vendor
mkdir -p "$out"
docker build -t "raven:$version" .
docker build -f docker/sim/Dockerfile -t "raven-logsim:$version" .
docker save "raven:$version" "raven-logsim:$version" -o "$out/raven-images-$version.tar"
cp docker-compose.yaml "$out/docker-compose.yaml"
cp -R packs schemas sources sinks "$out/"
if command -v sha256sum >/dev/null 2>&1; then
	(cd "$out" && sha256sum "raven-images-$version.tar" docker-compose.yaml > SHA256SUMS)
else
	(cd "$out" && shasum -a 256 "raven-images-$version.tar" docker-compose.yaml > SHA256SUMS)
fi
tar -C "$out" -czf "$out/raven-airgap-$version.tar.gz" "raven-images-$version.tar" docker-compose.yaml packs schemas sources sinks SHA256SUMS
