import re

from iota_helpers import deep_get


def get_info(event):
    fields = {
        "principal": "protoPayload.authenticationInfo.principalEmail",
        "project_id": "resource.labels.project_id",
        "caller_ip": "protoPayload.requestMetadata.callerIP",
        "user_agent": "protoPayload.requestMetadata.callerSuppliedUserAgent",
        "method_name": "protoPayload.methodName",
    }
    return {
        name: deep_get(event, *(path.split(".")), default=None)
        for name, path in fields.items()
    }


def get_k8s_info(event):
    pod_slug = deep_get(event, "protoPayload", "resourceName")
    if not pod_slug or not isinstance(pod_slug, str):
        return get_info(event) | {"namespace": "", "pod": ""}
    parts = pod_slug.split("/")
    if len(parts) >= 6 and parts[2] == "namespaces" and parts[4] == "pods":
        return get_info(event) | {"namespace": parts[3], "pod": parts[5]}
    return get_info(event) | {"namespace": "", "pod": ""}


def get_flow_log_info(event):
    fields = {
        "src_ip": "jsonPayload.connection.src_ip",
        "dest_ip": "jsonPayload.connection.dest_ip",
        "src_port": "jsonPayload.connection.src_port",
        "dest_port": "jsonPayload.connection.dest_port",
        "protocol": "jsonPayload.connection.protocol",
        "bytes_sent": "jsonPayload.bytes_sent",
        "reporter": "jsonPayload.reporter",
    }
    return {
        name: deep_get(event, *(path.split(".")), default=None)
        for name, path in fields.items()
    }


def gcp_alert_context(event):
    return {
        "project": deep_get(event, "resource", "labels", "project_id", default=""),
        "principal": deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail", default=""
        ),
        "caller_ip": deep_get(
            event, "protoPayload", "requestMetadata", "callerIP", default=""
        ),
        "methodName": deep_get(event, "protoPayload", "methodName", default=""),
        "resourceName": deep_get(event, "protoPayload", "resourceName", default=""),
        "serviceName": deep_get(event, "protoPayload", "serviceName", default=""),
    }


def get_binding_deltas(event):
    if event.get("protoPayload", {}).get("methodName") != "SetIamPolicy":
        return []

    service_data = event.get("protoPayload", {}).get("serviceData")
    if not service_data:
        return []

    binding_deltas = service_data.get("policyDelta", {}).get("bindingDeltas")
    if not binding_deltas:
        return []
    return binding_deltas


GKE_SYSTEM_SERVICE_ACCOUNT_PREFIXES = [
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:addon-manager",
    "system:serviceaccount:kube-system:",
    "system:serviceaccount:kube-public:",
    "system:serviceaccount:kube-node-lease:",
    "system:serviceaccount:gke-system:",
    "system:serviceaccount:gke-managed-system:",
    "system:serviceaccount:gmp-system:",
    "system:serviceaccount:gmp-public:",
    "system:serviceaccount:config-management-system:",
    "system:serviceaccount:istio-system:",
    "system:serviceaccount:asm-system:",
]

GKE_SYSTEM_SERVICE_ACCOUNT_PATTERNS = [
    re.compile(r"^[\d]+-compute@developer\.gserviceaccount\.com$"),
    re.compile(r"^container-engine-robot@.*\.iam\.gserviceaccount\.com$"),
    re.compile(r"^gke-[\d]+@.*\.iam\.gserviceaccount\.com$"),
    re.compile(r"^service-[\d]+@container-engine-robot\.iam\.gserviceaccount\.com$"),
    re.compile(r"^service-[\d]+@containerregistry\.iam\.gserviceaccount\.com$"),
    re.compile(r"^[\d]+@cloudservices\.gserviceaccount\.com$"),
    re.compile(r"^.*\.svc\.id\.goog\[kube-system/.*\]$"),
    re.compile(r"^.*\.svc\.id\.goog\[gke-system/.*\]$"),
    re.compile(r"^.*\.svc\.id\.goog\[gke-managed-system/.*\]$"),
]

GKE_SYSTEM_NAMESPACES = [
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "gke-system",
    "gke-managed-system",
    "gmp-system",
    "gmp-public",
    "config-management-system",
    "istio-system",
    "asm-system",
]


def is_gke_system_principal(principal_email):
    if not principal_email:
        return False

    for prefix in GKE_SYSTEM_SERVICE_ACCOUNT_PREFIXES:
        if principal_email.startswith(prefix):
            return True

    for pattern in GKE_SYSTEM_SERVICE_ACCOUNT_PATTERNS:
        if pattern.match(principal_email):
            return True

    return False


def is_gke_system_namespace(resource_name):
    if not resource_name:
        return False

    parts = resource_name.split("/")
    if len(parts) >= 4 and parts[2] == "namespaces":
        namespace = parts[3]
        return namespace in GKE_SYSTEM_NAMESPACES
    return False
