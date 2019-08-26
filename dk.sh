#!/bin/bash
# This script is a helper to re-tag and push our custom built images to gitlab
# Usage: ./dk.sh [tag you want] [tag you got from bin/docker-build (see docker images)]
# Example: ./dk.sh stable-2.5.0-acmpca dev-f6e8d3a7-x27s

echo "Pushing to $1"
docker tag gcr.io/linkerd-io/controller:$2 gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/controller:$1
docker push gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/controller:$1

docker tag gcr.io/linkerd-io/proxy:$2 gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/proxy:$1
docker push gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/proxy:$1

docker tag gcr.io/linkerd-io/grafana:$2 gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/grafana:$1
docker push gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/grafana:$1

docker tag gcr.io/linkerd-io/web:$2 gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/web:$1
docker push gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/web:$1

docker tag gcr.io/linkerd-io/cni-plugin:$2 gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/cni-plugin:$1
docker push gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/cni-plugin:$1

docker tag gcr.io/linkerd-io/cni-plugin:$2 gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/debug:$1
docker push gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/debug:$1

docker tag gcr.io/linkerd-io/cni-plugin:$2 gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/cli-bin:$1
docker push gitlab-registry.nordstrom.com/gtm/traffic-mesh-deploy/cli-bin:$1
