#!/usr/bin/env bash
# Kubernetes API activity in a lab namespace to populate k3s audit logs and exercise
# rules under rules/kubernetes/ when run through iota's parser (JSONL / pipeline).
#
# IMPORTANT — iota on the cluster:
#   Use --mode=audit-tail to read the live audit file (same path as below) and run kubernetes rules
#   with Slack alerts. Example:
#     /app/iota --mode=audit-tail --audit-log=/var/lib/rancher/k3s/server/logs/audit.log \
#       --rules=/app/rules/kubernetes --python=python3 --engine=/app/engines/iota/engine.py --state=/data/state.db
#   Kustomize overlay (canonical): iota-deployments/clusters/homelab-k3s-audit/ → namespace security-k3s-audit
#
#   Alternatively, --mode=once with JSONL extracted from audit.log still works for offline tests.
#
# kubeconfig (avoid "permission denied" on /etc/rancher/k3s/k3s.yaml):
#   mkdir -p "${HOME}/.kube"
#   sudo cp /etc/rancher/k3s/k3s.yaml "${HOME}/.kube/k3s-beelink.yaml"
#   sudo chown "${USER}" "${HOME}/.kube/k3s-beelink.yaml"
#   chmod 600 "${HOME}/.kube/k3s-beelink.yaml"
#   export KUBECONFIG="${HOME}/.kube/k3s-beelink.yaml"
#   Then you can use kubectl without sudo. Or keep using: sudo kubectl
#
# Note: pgrep kube-apiserver is often empty on k3s — the API server is embedded in k3s.
#
# Usage:
#   ./scripts/attack-sim/k3s-homelab-rule-sim.sh           # default namespace: security-k3s-audit
#   K8S_NAMESPACE=security-test ./scripts/attack-sim/k3s-homelab-rule-sim.sh
#   KUBECTL="sudo kubectl" ./scripts/attack-sim/k3s-homelab-rule-sim.sh
#
set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"
K8S_NAMESPACE="${K8S_NAMESPACE:-security-k3s-audit}"
AUDIT_LOG="${AUDIT_LOG:-/var/lib/rancher/k3s/server/logs/audit.log}"

if ! "${KUBECTL}" version --output=json >/dev/null 2>&1; then
	echo "kubectl failed. Fix permissions (see script header) or set KUBECTL=\"sudo kubectl\"" >&2
	exit 1
fi
if ! "${KUBECTL}" get namespace "${K8S_NAMESPACE}" >/dev/null 2>&1; then
	echo "Namespace ${K8S_NAMESPACE} does not exist. Apply the overlay first: kubectl apply -k /path/to/iota-deployments/clusters/homelab-k3s-audit" >&2
	exit 1
fi

k() {
	"${KUBECTL}" --namespace "${K8S_NAMESPACE}" "$@"
}

kc() {
	"${KUBECTL}" "$@"
}

echo "=== k3s homelab rule sim (namespace=${K8S_NAMESPACE}) ==="

echo "--- Step: pod for exec / cp / token read (busybox)"
k delete pod security-test-busybox --ignore-not-found --wait=true 2>/dev/null || true
k run security-test-busybox \
	--image=docker.io/library/busybox:1.36 \
	--restart=Never \
	--command -- /bin/sleep 3600
k wait --for=condition=Ready "pod/security-test-busybox" --timeout=120s

echo "--- Step: exec (k8s_exec_into_pod)"
k exec "pod/security-test-busybox" -- /bin/true

echo "--- Step: kubectl cp (k8s_kubectl_cp_operation)"
TMP_COPY="${TMPDIR:-/tmp}/security-test-hosts-copy"
k cp "${K8S_NAMESPACE}/security-test-busybox:/etc/hosts" "${TMP_COPY}" || true
rm -f "${TMP_COPY}" 2>/dev/null || sudo rm -f "${TMP_COPY}" 2>/dev/null || true

echo "--- Step: read SA token in exec (k8s_steal_serviceaccount_token)"
k exec "pod/security-test-busybox" -- /bin/cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null

k delete pod security-test-busybox --wait=true

echo "--- Step: long-lived SA token (k8s_serviceaccount_token_created)"
k delete serviceaccount security-test-demo-sa --ignore-not-found --wait=true 2>/dev/null || true
k create serviceaccount security-test-demo-sa
k create token security-test-demo-sa >/dev/null
k delete serviceaccount security-test-demo-sa --wait=true

echo "--- Step: RBAC (write / wildcard / pod-exec / node-proxy / clusterrolebinding / system: role)"
k delete role security-test-role-write --ignore-not-found --wait=true 2>/dev/null || true
k create role security-test-role-write --verb=create --resource=configmaps
k delete role security-test-role-write --wait=true

kc delete clusterrole security-test-clusterrole-wildcard --ignore-not-found --wait=true 2>/dev/null || true
kc create clusterrole security-test-clusterrole-wildcard --verb='*' --resource='*'
kc delete clusterrole security-test-clusterrole-wildcard --wait=true

k delete role security-test-role-pod-exec --ignore-not-found --wait=true 2>/dev/null || true
k create role security-test-role-pod-exec --verb=create --resource=pods/exec
k delete role security-test-role-pod-exec --wait=true

kc delete clusterrole security-test-clusterrole-node-proxy --ignore-not-found --wait=true 2>/dev/null || true
kc create clusterrole security-test-clusterrole-node-proxy --resource=nodes/proxy --verb=get
kc delete clusterrole security-test-clusterrole-node-proxy --wait=true

kc delete clusterrolebinding security-test-clusterrolebinding-admin --ignore-not-found --wait=true 2>/dev/null || true
kc create clusterrolebinding security-test-clusterrolebinding-admin \
	--clusterrole=cluster-admin \
	--user=security-test-dummy-user
kc delete clusterrolebinding security-test-clusterrolebinding-admin --wait=true

kc delete clusterrole system:security-test-lab-role --ignore-not-found --wait=true 2>/dev/null || true
kc create clusterrole system:security-test-lab-role --verb=get --resource=configmaps
kc patch clusterrole system:security-test-lab-role --patch '{"rules":[]}'
kc delete clusterrole system:security-test-lab-role --wait=true

echo "--- Step: Service + Ingress without TLS (k8s_ingress_without_tls)"
k delete ingress security-test-ingress --ignore-not-found --wait=true 2>/dev/null || true
k delete service security-test-svc --ignore-not-found --wait=true 2>/dev/null || true
k create service clusterip security-test-svc --tcp=80:80
k create ingress security-test-ingress \
	--class=nginx \
	--rule="example.invalid/*=security-test-svc:80"
k delete ingress security-test-ingress --wait=true
k delete service security-test-svc --wait=true

echo "--- Step: NodePort (k8s_service_nodeport)"
k delete deployment security-test-nginx --ignore-not-found --wait=true 2>/dev/null || true
k delete service security-test-service-nodeport --ignore-not-found --wait=true 2>/dev/null || true
k create deployment security-test-nginx --image=docker.io/library/nginx:1.25-alpine
k wait --for=condition=Available "deployment/security-test-nginx" --timeout=120s
k expose deployment security-test-nginx \
	--name=security-test-service-nodeport \
	--port=80 \
	--target-port=80 \
	--type=NodePort
k delete service security-test-service-nodeport --wait=true
k delete deployment security-test-nginx --wait=true

echo "--- Step: CronJob (k8s_cronjob_created_or_modified)"
k delete cronjob security-test-cronjob --ignore-not-found --wait=true 2>/dev/null || true
k create cronjob security-test-cronjob \
	--image=docker.io/library/busybox:1.36 \
	--schedule="*/30 * * * *" \
	-- /bin/sleep 30
k delete cronjob security-test-cronjob --wait=true

echo "--- Step: DaemonSet (k8s_daemonset_created)"
k delete daemonset security-test-daemonset --ignore-not-found --wait=true 2>/dev/null || true
k apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: security-test-daemonset
  namespace: ${K8S_NAMESPACE}
spec:
  selector:
    matchLabels:
      app: security-test-daemonset
  template:
    metadata:
      labels:
        app: security-test-daemonset
    spec:
      containers:
        - name: pause
          image: registry.k8s.io/pause:3.9
EOF
k delete daemonset security-test-daemonset --wait=true

echo "--- Step: privileged pod (k8s_privileged_pod_created)"
k delete pod security-test-pod-privileged --ignore-not-found --wait=true 2>/dev/null || true
k apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: security-test-pod-privileged
  namespace: ${K8S_NAMESPACE}
spec:
  containers:
    - name: main
      image: docker.io/library/busybox:1.36
      command: ["/bin/sleep", "3600"]
      securityContext:
        privileged: true
EOF
k delete pod security-test-pod-privileged --wait=true

echo "--- Step: hostPath pod (k8s_pod_hostpath_volume)"
k delete pod security-test-pod-hostpath --ignore-not-found --wait=true 2>/dev/null || true
k apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: security-test-pod-hostpath
  namespace: ${K8S_NAMESPACE}
spec:
  containers:
    - name: main
      image: docker.io/library/busybox:1.36
      command: ["/bin/sleep", "3600"]
      volumeMounts:
        - name: host
          mountPath: /host-tmp
  volumes:
    - name: host
      hostPath:
        path: /tmp
        type: DirectoryOrCreate
EOF
k delete pod security-test-pod-hostpath --wait=true

echo "--- Step: ValidatingWebhookConfiguration (k8s_admission_controller_created)"
kc delete validatingwebhookconfiguration security-test-validating-webhook-configuration --ignore-not-found --wait=true 2>/dev/null || true
kc apply -f - <<'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: security-test-validating-webhook-configuration
webhooks:
  - name: security-test.example.invalid
    clientConfig:
      url: https://example.invalid/validate
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    admissionReviewVersions: ["v1"]
    sideEffects: None
EOF
kc delete validatingwebhookconfiguration security-test-validating-webhook-configuration --wait=true

echo "=== done ==="
echo ""
echo "Verify audit lines (on the node):"
echo "  sudo tail -n 20 ${AUDIT_LOG}"
echo ""
echo "Run iota against extracted audit JSONL (does not use SQS/Slack by itself):"
echo "  # extract recent Event lines, then:"
echo "  ./bin/iota --mode=once --jsonl=./audit-sample.jsonl --rules=rules/kubernetes --python=python3 --engine=engines/iota/engine.py"
echo ""
