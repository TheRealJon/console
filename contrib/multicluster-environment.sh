# shellcheck shell=bash

BRIDGE_MANAGED_CLUSTER_PUBLIC_URL=$(oc whoami --show-server)
export BRIDGE_MANAGED_CLUSTER_PUBLIC_URL

BRIDGE_MANAGED_CLUSTER_BEARER_TOKEN=$(oc whoami --show-token)
export BRIDGE_MANAGED_CLUSTER_BEARER_TOKEN

BRIDGE_MANAGED_CLUSTER_THANOS_URL=$(oc -n openshift-config-managed get configmap monitoring-shared-config -o jsonpath='{.data.thanosPublicURL}')
export BRIDGE_MANAGED_CLUSTER_THANOS_URL

echo "Using managed cluster $BRIDGE_MANAGED_CLUSTER_PUBLIC_URL"
