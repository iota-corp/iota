import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
import re
from iota_helpers import deep_get

# Common ransomware note filename patterns
RANSOM_NOTE_PATTERNS = [
    # Explicit ransomware-related terms
    # RANSOM_NOTE.txt, PAYMENT_INFO.html
    r"(?i)(ransom|payment)[_-]?(note|info|instructions?).*\.(txt|html?)$",
    # Decrypt/restore with specific action words
    # HOW_TO_DECRYPT_FILES.txt
    r"(?i)how[_-]?to[_-]?(decrypt|restore|recover)[_-]?(your[_-]?)?files.*\.(txt|html?)$",
    # DECRYPT_INSTRUCTIONS.txt
    r"(?i)decrypt[_-]?(instructions?|guide|info|your[_-]?files).*\.(txt|html?)$",
    # RESTORE_INSTRUCTIONS.txt
    r"(?i)restore[_-]?(instructions?|guide|info|your[_-]?files).*\.(txt|html?)$",
    # RECOVERY_INSTRUCTIONS.txt
    r"(?i)recovery[_-]?(instructions?|key|guide).*\.(txt|html?)$",
    # Files encrypted/locked messages
    # FILES_ENCRYPTED.txt, ALL_FILES_HAVE_BEEN_ENCRYPTED.txt
    r"(?i)(all[_-]?)?files?[_-]?(have[_-]?been[_-]?)?(encrypted|locked).*\.(txt|html?)$",
    # YOUR_FILES_ARE_ENCRYPTED.txt
    r"(?i)your[_-]?files?[_-]?(are|have[_-]?been)[_-]?(encrypted|locked).*\.(txt|html?)$",
    # DATA_ENCRYPTED.txt
    r"(?i)data[_-]?(has[_-]?been[_-]?)?(encrypted|locked).*\.(txt|html?)$",
    # Unlock-related (common in ransomware)
    # UNLOCK_INSTRUCTIONS.txt
    r"(?i)unlock[_-]?(instructions?|guide|your[_-]?files).*\.(txt|html?)$",
    # Help decrypt/restore (specific to ransomware)
    # HELP_DECRYPT_YOUR_FILES.txt
    r"(?i)help[_-]?(restore|decrypt|recover)[_-]?(your[_-]?)?files.*\.(txt|html?)$",
]

COMPILED_PATTERNS = [re.compile(pattern) for pattern in RANSOM_NOTE_PATTERNS]


def rule(event):
    if deep_get(event, "protoPayload", "serviceName") != "storage.googleapis.com":
        return False

    # Focus on the create operation (the actual re-encryption)
    method = deep_get(event, "protoPayload", "methodName", default="<UNKNOWN_METHOD")
    if method != "storage.objects.create":
        return False

    # Check for filename
    resource = deep_get(event, "protoPayload", "resourceName", default="")
    obj_name = (
        resource.split("/objects/")[-1] if "/objects/" in resource else "<UNKNOWN_FILE>"
    )
    return any(pattern.match(obj_name) for pattern in COMPILED_PATTERNS)


def title(event):
    resource = deep_get(event, "protoPayload", "resourceName", default="")
    obj_name = (
        resource.split("/objects/")[-1] if "/objects/" in resource else "<UNKNOWN_FILE>"
    )
    bucket = deep_get(
        event, "resource", "labels", "bucket_name", default="<UNKNOWN_BUCKET>"
    )
    user = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<UNKNOWN_USER>",
    )
    return (
        f"[GCP] Potential ransomware note uploaded to GCS bucket: "
        f"[{obj_name}] in bucket [{bucket}] by user [{user}]"
    )
