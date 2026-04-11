import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    if deep_get(event, "protoPayload", "serviceName") != "cloudkms.googleapis.com":
        return False

    method = deep_get(event, "protoPayload", "methodName", default="<UNKNOWN_METHOD>")

    # Direct key version destruction
    if method == "DestroyCryptoKeyVersion":
        return True

    # Key version state change, check for dangerous states
    if method == "UpdateCryptoKeyVersion":
        if deep_get(event, "protoPayload", "request", "updateMask") != "state":
            return False

        crypto_key_state = deep_get(
            event,
            "protoPayload",
            "request",
            "cryptoKeyVersion",
            "state",
            default="<UNKNOWN_STATE>",
        )
        dangerous_states = ["DISABLED", "DESTROY_SCHEDULED", "DESTROYED"]
        return crypto_key_state in dangerous_states

    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )
    key = deep_get(
        event, "protoPayload", "request", "cryptoKeyVersion", "name", default="Unknown"
    )
    return f"GCP KMS key [{key}] version disabled or destroyed by {actor}"


def alert_context(event):
    return {
        "actor": deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail"
        ),
        "kms_key_version": deep_get(event, "protoPayload", "resourceName"),
        "new_state": deep_get(
            event, "protoPayload", "request", "cryptoKeyVersion", "state"
        ),
        "source_ip": deep_get(event, "protoPayload", "requestMetadata", "callerIp"),
        "project": deep_get(event, "resource", "labels", "project_id"),
        "key_ring": deep_get(event, "resource", "labels", "key_ring_id"),
        "crypto_key": deep_get(event, "resource", "labels", "crypto_key_id"),
    }
