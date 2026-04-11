"""Kubernetes unified detections (EKS audit JSON, GKE via GCP.AuditLog k8s.io)."""

from typing import Any, Dict, Optional

from iota_helpers import deep_get

SYSTEM_NAMESPACES = {"kube-system", "gke-system", "kube-node-lease", "kube-public"}

SENSITIVE_HOSTPATHS = {
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/etc/kubernetes",
    "/etc/",
    "/",
    "/proc",
    "/sys",
    "/root",
    "/home/admin",
    "/var/run/docker.sock",
    "/var/run/crio/crio.sock",
    "/run/containerd/containerd.sock",
}

SYSTEM_IDENTITY_PREFIXES = [
    ".iam.gserviceaccount.com",
    "system:serviceaccount:kube-system:",
    "eks:",
    "masterclient",
    "gke-",
    "azure-",
]

_EKS_UDM_KEYS = {
    "annotations": ("annotations",),
    "apiGroup": ("objectRef", "apiGroup"),
    "apiVersion": ("objectRef", "apiVersion"),
    "namespace": ("objectRef", "namespace"),
    "resource": ("objectRef", "resource"),
    "name": ("objectRef", "name"),
    "subresource": ("objectRef", "subresource"),
    "requestURI": ("requestURI",),
    "responseStatus": ("responseStatus",),
    "sourceIPs": ("sourceIPs",),
    "username": ("user", "username"),
    "userAgent": ("userAgent",),
    "verb": ("verb",),
    "requestObject": ("requestObject",),
    "responseObject": ("responseObject",),
    "containers": ("requestObject", "spec", "containers"),
    "volumes": ("requestObject", "spec", "volumes"),
    "hostIPC": ("requestObject", "spec", "hostIPC"),
    "hostNetwork": ("requestObject", "spec", "hostNetwork"),
    "hostPID": ("requestObject", "spec", "hostPID"),
    "webhooks": ("requestObject", "webhooks"),
    "serviceType": ("requestObject", "spec", "type"),
}


def _is_eks_audit_event(event: dict) -> bool:
    if event.get("p_log_type") == "Amazon.EKS.Audit":
        return True
    av = str(event.get("apiVersion", ""))
    # Prefix match only (avoid substring matches like "evilaudit.k8s.io/v1")
    if event.get("kind") != "Event":
        return False
    return av == "audit.k8s.io/v1" or av.startswith("audit.k8s.io/")


def _is_gcp_k8s_event(event: dict) -> bool:
    return (
        event.get("p_log_type") == "GCP.AuditLog"
        and deep_get(event, "protoPayload", "serviceName", default="") == "k8s.io"
    )


def _gcp_k8s_udm(event: dict, key: str, default=None):
    if key == "verb":
        method_name = str(deep_get(event, "protoPayload", "methodName", default=""))
        return method_name.rsplit(".", maxsplit=1)[-1] if method_name else default
    if key == "username":
        return _gcp_get_actor_user(event)
    if key == "sourceIPs":
        ips = _gcp_get_source_ips(event)
        return ips if ips else default
    if key == "userAgent":
        return deep_get(
            event,
            "protoPayload",
            "requestMetadata",
            "callerSuppliedUserAgent",
            default=default,
        )
    if key == "responseStatus":
        return deep_get(event, "protoPayload", "status", default=default)
    if key == "requestURI":
        return _gcp_get_request_uri(event) or default
    if key == "requestObject":
        return deep_get(event, "protoPayload", "request", default=default)
    if key == "responseObject":
        return deep_get(event, "protoPayload", "response", default=default)
    if key == "annotations":
        return deep_get(event, "labels", default=default)
    if key == "apiGroup":
        return _gcp_get_api_group(event) or default
    if key == "apiVersion":
        return _gcp_get_api_version(event) or default
    if key == "namespace":
        return _gcp_get_namespace(event) or default
    if key == "resource":
        return _gcp_get_resource(event) or default
    if key == "name":
        return _gcp_get_name(event) or default
    if key == "subresource":
        return _gcp_get_subresource(event) or default
    if key == "containers":
        return deep_get(
            event, "protoPayload", "request", "spec", "containers", default=default
        )
    if key == "volumes":
        return deep_get(
            event, "protoPayload", "request", "spec", "volumes", default=default
        )
    if key == "hostIPC":
        return deep_get(
            event, "protoPayload", "request", "spec", "hostIPC", default=default
        )
    if key == "hostNetwork":
        return deep_get(
            event, "protoPayload", "request", "spec", "hostNetwork", default=default
        )
    if key == "hostPID":
        return deep_get(
            event, "protoPayload", "request", "spec", "hostPID", default=default
        )
    if key == "webhooks":
        return deep_get(event, "protoPayload", "request", "webhooks", default=default)
    if key == "serviceType":
        return deep_get(
            event, "protoPayload", "request", "spec", "type", default=default
        )
    return default


def _gcp_get_api_group(event: dict) -> str:
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        return resource_name.split("/", maxsplit=1)[0]
    except (IndexError, ValueError, AttributeError):
        return ""


def _gcp_get_api_version(event: dict) -> str:
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        return resource_name.split("/")[1]
    except (IndexError, ValueError, AttributeError):
        return ""


def _gcp_get_namespace(event: dict) -> str:
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        parts = resource_name.split("/")
        if len(parts) >= 4 and parts[2] == "namespaces":
            return parts[3]
        return ""
    except (IndexError, ValueError, AttributeError):
        return ""


def _gcp_get_resource(event: dict) -> str:
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        parts = resource_name.split("/")
        if len(parts) >= 5:
            return parts[4]
        if len(parts) >= 3:
            return parts[2]
        return ""
    except (IndexError, ValueError, AttributeError):
        return ""


def _gcp_get_name(event: dict) -> str:
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        parts = resource_name.split("/")
        if len(parts) >= 6:
            return parts[5]
        if len(parts) >= 4:
            return parts[3]
        return ""
    except (IndexError, ValueError, AttributeError):
        return ""


def _gcp_get_subresource(event: dict) -> str:
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        parts = resource_name.split("/")
        if len(parts) > 6:
            return parts[6]
        return ""
    except (IndexError, ValueError, AttributeError):
        return ""


def _gcp_get_request_uri(event: dict) -> str:
    resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
    if not resource_name:
        return ""
    return "/apis/" + resource_name


def _gcp_get_source_ips(event: dict) -> list:
    caller_ip = deep_get(
        event, "protoPayload", "requestMetadata", "callerIP", default=None
    )
    if caller_ip:
        return [caller_ip]
    return []


def _gcp_get_actor_user(event: dict) -> str:
    authentication_info = (
        deep_get(event, "protoPayload", "authenticationInfo", default={}) or {}
    )
    if principal_email := authentication_info.get("principalEmail"):
        return principal_email
    if principal_subject := authentication_info.get("principalSubject"):
        return principal_subject
    if authority := authentication_info.get("authoritySelector"):
        return authority
    return "<UNKNOWN ACTOR USER>"


def k8s_udm(event: dict, key: str, default=None):
    if _is_gcp_k8s_event(event):
        v = _gcp_k8s_udm(event, key, default)
        return default if v is None else v
    if _is_eks_audit_event(event):
        if key in _EKS_UDM_KEYS:
            v = deep_get(event, *_EKS_UDM_KEYS[key])
            return default if v is None else v
        return default
    return default


def k8s_alert_context(event: dict, extra_fields=None) -> dict:
    context = {
        "username": k8s_udm(event, "username"),
        "sourceIPs": k8s_udm(event, "sourceIPs"),
        "userAgent": k8s_udm(event, "userAgent"),
        "namespace": k8s_udm(event, "namespace"),
        "verb": k8s_udm(event, "verb"),
        "resource": k8s_udm(event, "resource"),
        "requestURI": k8s_udm(event, "requestURI"),
        "responseStatus": k8s_udm(event, "responseStatus"),
        "cluster": event.get("p_source_label"),
    }
    if extra_fields:
        context.update(extra_fields)
    return context


def is_system_namespace(namespace: Optional[str]) -> bool:
    if not namespace:
        return False
    return namespace in SYSTEM_NAMESPACES


def is_system_principal(username: Optional[str]) -> bool:
    if not username:
        return False
    if username.startswith(tuple(SYSTEM_IDENTITY_PREFIXES)):
        return True
    if username in ("masterclient", "aksService"):
        return True
    if username.startswith("system:") and "serviceaccount" not in username:
        return True
    return False


def is_failed_request(response_status) -> bool:
    if not response_status:
        return False
    status_code = response_status.get("code")
    if not isinstance(status_code, int):
        return False
    if status_code >= 400:
        return True
    if 1 <= status_code <= 16:
        return True
    return False


def is_k8s_log(event: dict) -> bool:
    log_type = event.get("p_log_type", "")
    if log_type == "Amazon.EKS.Audit":
        return True
    if log_type == "GCP.AuditLog":
        return deep_get(event, "protoPayload", "serviceName", default="") == "k8s.io"
    if log_type == "Azure.MonitorActivity":
        category = event.get("category", "")
        return category in ("kube-audit", "kube-audit-admin")
    return False


def get_cluster_label(event: dict, default: str = "<UNKNOWN_CLUSTER>") -> str:
    return event.get("p_source_label", default)


def is_privileged_container(containers) -> bool:
    if not containers:
        return False
    for container in containers:
        security_context = container.get("securityContext", {})
        if security_context.get("privileged") is True:
            return True
        if security_context.get("runAsNonRoot") is False:
            return True
        if security_context.get("runAsUser") == 0:
            return True
    return False


def has_hostpath_volume(volumes) -> bool:
    if not volumes:
        return False
    return any("hostPath" in volume for volume in volumes)


def get_hostpath_paths(volumes) -> list:
    if not volumes:
        return []
    paths = []
    for volume in volumes:
        if "hostPath" in volume:
            path = volume.get("hostPath", {}).get("path")
            if path:
                paths.append(path)
    return paths


def is_sensitive_hostpath(path: Optional[str]) -> bool:
    if not path:
        return False
    for sensitive_path in SENSITIVE_HOSTPATHS:
        if path == sensitive_path or path.startswith(sensitive_path + "/"):
            return True
    return False


def get_resource_name(event: dict, default: str = "<UNKNOWN>") -> str:
    return k8s_udm(event, "name") or default


def get_pod_name(event: dict, default: str = "<UNKNOWN_POD>") -> str:
    name = k8s_udm(event, "name")
    if name:
        return name
    response_object = k8s_udm(event, "responseObject") or {}
    name = response_object.get("metadata", {}).get("name")
    if name:
        return name
    request_object = k8s_udm(event, "requestObject") or {}
    name = request_object.get("metadata", {}).get("name")
    if name:
        return name
    return default


def _extract_container_summary(container: Dict[str, Any]) -> Dict[str, Any]:
    env_vars = []
    secret_refs = []
    for env_var in container.get("env", []):
        env_name = env_var.get("name")
        if env_name:
            env_vars.append(env_name)
            value_from = env_var.get("valueFrom", {})
            if "secretKeyRef" in value_from:
                secret_refs.append(
                    {
                        "env_var": env_name,
                        "secret_name": value_from["secretKeyRef"].get("name"),
                        "secret_key": value_from["secretKeyRef"].get("key"),
                    }
                )

    return {
        "name": container.get("name"),
        "image": container.get("image"),
        "ports": [p.get("containerPort") for p in container.get("ports", [])],
        "env_vars": env_vars,
        "secret_refs": secret_refs if secret_refs else None,
        "volume_mounts": [
            {"path": vm.get("mountPath"), "name": vm.get("name")}
            for vm in container.get("volumeMounts", [])
            if vm.get("mountPath") and vm.get("name")
        ],
        "security_context": container.get("securityContext", {}),
        "resources": container.get("resources", {}),
    }


def _extract_volume_info(volume: Dict[str, Any]) -> Dict[str, Any]:
    vol_info = {"name": volume.get("name")}
    if "hostPath" in volume:
        vol_info["type"] = "hostPath"
        path = volume["hostPath"].get("path")
        vol_info["path"] = path
        vol_info["sensitive"] = is_sensitive_hostpath(path) if path else False
    elif "configMap" in volume:
        vol_info["type"] = "configMap"
        vol_info["source"] = volume["configMap"].get("name")
    elif "secret" in volume:
        vol_info["type"] = "secret"
        vol_info["source"] = volume["secret"].get("secretName")
    else:
        vol_info["type"] = "other"
        vol_info["keys"] = list(volume.keys())
    return vol_info


def get_pod_context_fields(event: dict) -> Dict[str, Any]:
    request_object = k8s_udm(event, "requestObject") or {}
    pod_metadata = request_object.get("metadata", {})
    pod_spec = request_object.get("spec", {})

    containers = k8s_udm(event, "containers") or []
    container_summaries = (
        [_extract_container_summary(c) for c in containers] if containers else []
    )

    owner_refs = [
        {"kind": ref.get("kind"), "name": ref.get("name")}
        for ref in pod_metadata.get("ownerReferences", [])
    ]

    volumes = [_extract_volume_info(v) for v in pod_spec.get("volumes", [])]

    return {
        "pod_name": get_pod_name(event),
        "owner_references": owner_refs if owner_refs else None,
        "host_settings": {
            "hostPID": pod_spec.get("hostPID", False),
            "hostIPC": pod_spec.get("hostIPC", False),
            "hostNetwork": pod_spec.get("hostNetwork", False),
        },
        "containers": container_summaries if container_summaries else None,
        "volumes": volumes if volumes else None,
    }


class _EnrichmentIPInfoView:
    """ASN/domain from `p_enrichment.ipinfo` when the pipeline attaches GeoIP/ASN data."""

    def __init__(self, data: Dict[str, Any]) -> None:
        self._d = data or {}

    def asn(self, field: str) -> list:
        v = self._d.get(field)
        if v is None:
            v = (self._d.get("asns") or {}).get(field)
        if isinstance(v, list):
            return [str(x) for x in v]
        if v is not None and v != "":
            return [str(v)]
        return []

    def domain(self, field: str) -> list:
        v = self._d.get("domain_" + field) or (self._d.get("domains") or {}).get(field)
        if isinstance(v, list):
            return [str(x) for x in v]
        if v is not None and v != "":
            return [str(v)]
        return []


def get_ipinfo_asn(event: dict):
    """ASN helper: uses `p_enrichment.ipinfo` if present; no live lookups."""
    raw = deep_get(event, "p_enrichment", "ipinfo", default=None)
    if not raw:
        return None
    return _EnrichmentIPInfoView(raw)
