#!/usr/bin/env bash
# Lint, template, and validate the nanoidp chart: helm lint/template
# against default values and every fixture under charts/nanoidp/ci/,
# kubeconform validation of the rendered manifests against the real
# Kubernetes API schema (no cluster involved), the values.schema.json
# rejection check, and a handful of chart-specific behavioral assertions.
#
# Runs identically locally and in .github/workflows/helm.yml. Locally,
# install the two extra tools once (e.g. `brew install kubeconform yq`).
# One exception: the NOTES.txt assertions need `helm install --dry-run=
# client` to succeed, which Helm 3 (unlike 4) can only do against a
# reachable cluster. With Helm 3 and no cluster, that step prints a skip
# message and moves on instead of failing.
set -euo pipefail

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI_DIR="$CHART_DIR/ci"

for tool in helm kubeconform yq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: '$tool' is required on PATH (e.g. 'brew install $tool')" >&2
    exit 1
  fi
done

# Kubernetes version the rendered manifests are validated against.
K8S_VERSION="${K8S_VERSION:-1.30.0}"

# Helm 3's --dry-run=client for `helm install` still contacts the
# cluster to fill in defaults and fails with "Kubernetes cluster
# unreachable" when there is none. Helm 4 dropped that requirement. Only
# major 3 needs the fallback below, 4 (or whatever comes after) doesn't.
HELM_MAJOR="$(helm version --short | sed -E 's/^v?([0-9]+).*/\1/')"

check_values() {
  local label="$1"
  shift
  echo "=== $label ==="
  helm lint "$CHART_DIR" "$@"
  helm template "$CHART_DIR" "$@" >/tmp/nanoidp-rendered.yaml
  kubeconform -strict -kubernetes-version "$K8S_VERSION" -summary /tmp/nanoidp-rendered.yaml
}

for values in "$CI_DIR"/*.yaml; do
  check_values "$(basename "$values")" -f "$values"
done

echo "=== values.schema.json rejects a bad type ==="
if helm template "$CHART_DIR" --set ingress.create=yes >/dev/null 2>&1; then
  echo "expected values.schema.json to reject ingress.create=yes, but it rendered" >&2
  exit 1
fi
echo "ok: ingress.create=yes rejected"

echo "=== values.schema.json requires configFiles.users/settings unless existingSecret is set ==="
if helm template "$CHART_DIR" >/dev/null 2>&1; then
  echo "expected values.schema.json to reject empty configFiles.users/settings with no existingSecret, but it rendered" >&2
  exit 1
fi
echo "ok: empty configFiles.users/settings rejected (bare default values)"

assert_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: $desc: expected '$expected', got '$actual'" >&2
    exit 1
  fi
  echo "ok: $desc"
}

echo "=== behavioral assertions (values-full.yaml) ==="
full="$(helm template "$CHART_DIR" -f "$CI_DIR/values-full.yaml")"
assert_eq "single replica" \
  "$(yq 'select(.kind == "Deployment") | .spec.replicas' <<<"$full")" "1"
assert_eq "Recreate strategy" \
  "$(yq 'select(.kind == "Deployment") | .spec.strategy.type' <<<"$full")" "Recreate"
assert_eq "INGRESS_HOST injected" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "INGRESS_HOST") | .value' <<<"$full")" \
  "idp.example.com"
assert_eq "INGRESS_URL scheme (no tls -> http)" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "INGRESS_URL") | .value' <<<"$full")" \
  "http://idp.example.com"
assert_eq "NANOIDP_MANAGEMENT_SECRET present (complete example is authenticated)" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "NANOIDP_MANAGEMENT_SECRET") | .name' <<<"$full")" \
  "NANOIDP_MANAGEMENT_SECRET"

full_tls="$(helm template "$CHART_DIR" -f "$CI_DIR/values-full.yaml" --set ingress.tls.secretName=idp-tls)"
assert_eq "INGRESS_URL scheme (tls set -> https)" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "INGRESS_URL") | .value' <<<"$full_tls")" \
  "https://idp.example.com"

full_changed="$(helm template "$CHART_DIR" -f "$CI_DIR/values-full.yaml" --set-string configFiles.users="users:
  admin:
    password: admin
  bob:
    password: bob")"
checksum_a="$(yq 'select(.kind == "Deployment") | .spec.template.metadata.annotations."checksum/config"' <<<"$full")"
checksum_b="$(yq 'select(.kind == "Deployment") | .spec.template.metadata.annotations."checksum/config"' <<<"$full_changed")"
if [ "$checksum_a" = "$checksum_b" ] || [ -z "$checksum_a" ]; then
  echo "FAIL: checksum/config did not change with configFiles.users (got '$checksum_a' both times)" >&2
  exit 1
fi
echo "ok: checksum/config changes with configFiles.users"

echo "=== behavioral assertions (values-existing-secret.yaml) ==="
existing="$(helm template "$CHART_DIR" -f "$CI_DIR/values-existing-secret.yaml")"
assert_eq "no generated Secret with existingSecret set" \
  "$(yq 'select(.kind == "Secret") | .kind' <<<"$existing" | wc -l | tr -d ' ')" "0"
assert_eq "volume references the existing Secret name" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.volumes[0].secret.secretName' <<<"$existing")" \
  "my-existing-nanoidp-config"
assert_eq "no checksum/config with existingSecret set" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.metadata.annotations."checksum/config"' <<<"$existing")" \
  "null"

echo "=== behavioral assertions (values-minimal.yaml) ==="
default="$(helm template "$CHART_DIR" -f "$CI_DIR/values-minimal.yaml")"
assert_eq "securityContext.allowPrivilegeEscalation" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation' <<<"$default")" \
  "false"
assert_eq "securityContext drops all capabilities" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].securityContext.capabilities.drop[0]' <<<"$default")" \
  "ALL"
assert_eq "securityContext.seccompProfile" \
  "$(yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].securityContext.seccompProfile.type' <<<"$default")" \
  "RuntimeDefault"

with_ingress="$(helm template "$CHART_DIR" -f "$CI_DIR/values-minimal.yaml" --set ingress.create=true --set ingress.host=idp.example.com)"
assert_eq "no ingressClassName by default" \
  "$(yq 'select(.kind == "Ingress") | .spec.ingressClassName' <<<"$with_ingress")" "null"
with_class="$(helm template "$CHART_DIR" -f "$CI_DIR/values-minimal.yaml" --set ingress.create=true --set ingress.host=idp.example.com --set ingress.className=nginx)"
assert_eq "ingress.className renders as ingressClassName" \
  "$(yq 'select(.kind == "Ingress") | .spec.ingressClassName' <<<"$with_class")" "nginx"

echo "=== NOTES.txt ==="
# helm template does not render NOTES.txt at all, only helm install/
# upgrade (or --dry-run=client) do.

# Runs `helm install --dry-run=client "$@"`, leaving its output in
# $NOTES_OUT for the caller. Must be called outside a command
# substitution, or its `exit 1` on a genuine failure only ends that
# subshell instead of the script. Returns 0 on success, 1 (with a skip
# message on stderr) when Helm 3 has no cluster to talk to, and
# otherwise prints the failure and exits the whole script, same as any
# other assertion here.
notes_or_skip() {
  local desc="$1"
  shift
  if NOTES_OUT="$(helm install ci-check "$CHART_DIR" -f "$CI_DIR/values-minimal.yaml" --dry-run=client "$@" 2>&1)"; then
    return 0
  fi
  if [ "$HELM_MAJOR" -lt 4 ] && grep -q 'Kubernetes cluster unreachable' <<<"$NOTES_OUT"; then
    echo "skip: $desc (Helm $HELM_MAJOR's --dry-run=client needs a reachable cluster; none available here)" >&2
    return 1
  fi
  printf '%s\n' "$NOTES_OUT" >&2
  echo "FAIL: $desc" >&2
  exit 1
}

if notes_or_skip "NOTES.txt (default values)"; then
  if ! grep -q 'WARNING: the resolved image tag is "0.0.0"' <<<"$NOTES_OUT"; then
    echo "FAIL: NOTES.txt did not warn about the 0.0.0 placeholder tag with default values" >&2
    exit 1
  fi
  echo "ok: NOTES.txt warns about the 0.0.0 placeholder tag by default"

  notes_or_skip "NOTES.txt (image.tag set)" --set image.tag=v3.0.0
  if grep -q 'WARNING: the resolved image tag is "0.0.0"' <<<"$NOTES_OUT"; then
    echo "FAIL: NOTES.txt still warned about 0.0.0 with an explicit image.tag set" >&2
    exit 1
  fi
  echo "ok: NOTES.txt warning is absent with an explicit image.tag"
fi

echo "All nanoidp chart CI checks passed."
