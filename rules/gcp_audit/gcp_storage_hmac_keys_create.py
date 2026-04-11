import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_walk


def rule(event):
    auth_info = deep_walk(event, "protoPayload", "authorizationInfo", default=[])
    auth_info = auth_info if isinstance(auth_info, list) else [auth_info]

    for auth in auth_info:
        if (
            auth.get("granted", False)
            and auth.get("permission", "") == "storage.hmacKeys.create"
        ):
            return True
    return False
