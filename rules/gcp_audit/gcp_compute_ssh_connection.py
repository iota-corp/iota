import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event) -> bool:
    service_name = deep_get(event, "protoPayload", "serviceName", default="")
    method_name = deep_get(event, "protoPayload", "methodName", default="")

    if service_name == "iap.googleapis.com" and method_name == "AuthorizeUser":
        return True

    if service_name == "oslogin.googleapis.com":
        if any(
            [
                method_name.endswith(".CheckPolicy"),
                method_name.endswith(".ContinueSession"),
            ]
        ):
            return True

    if service_name == "compute.googleapis.com":
        # Check attempts to add SSH keys to the VM
        # setCommonInstanceMetadata is triggered when SSHing from a remote device
        # setMetadata is triggered when SSHing from the GCP Console
        ssh_keys = {
            "ssh-keys",
            "sshKeys",
        }  # Fields indicating the SSH keys were modified
        if any(
            [
                method_name.endswith(".setCommonInstanceMetadata"),
                method_name.endswith(".setMetadata"),
            ]
        ):
            # The metadata delta field could be for the project or the instance, and could indicate
            # something was removed or modified. We need to check all possible paths to the field
            # we need.
            modified_keys = set()
            for field1 in ["projectMetadataDelta", "instanceMetadataDelta"]:
                for field2 in ["addedMetadataKeys", "modifiedMetadataKeys"]:
                    modified_keys.update(
                        set(
                            deep_get(
                                event,
                                "protoPayload",
                                "metadata",
                                field1,
                                field2,
                                default=[],
                            )
                        )
                    )
            return bool(modified_keys & ssh_keys)

    # Serial console API: global or regional hostnames (e.g. us-central1-ssh-serialport.googleapis.com).
    # Use prefix/suffix checks, not bare substring, to satisfy security scanners.
    if service_name in {
        "ssh-serialport.googleapis.com",
        "serialport.googleapis.com",
    } or (service_name.endswith("-ssh-serialport.googleapis.com")):
        if method_name == "google.ssh-serialport.v1.connect":
            return (
                "succeeded"
                in deep_get(
                    event, "protoPayload", "status", "message", default=""
                ).lower()
            )

    return False


def alert_context(event) -> dict:
    instance_info = get_instance_info(event)
    context = {
        "instance_id": instance_info.get("id", "UNKNOWN INSTANCE ID"),
        "instance_name": instance_info.get("name", "UNKNOWN INSTANCE NAME"),
    }
    return gcp_alert_context(event) | context


def get_instance_info(event) -> dict:
    service_name = deep_get(event, "protoPayload", "serviceName", default="")

    context = {
        "id": "UNKNOWN INSTANCE ID",
        "name": "UNKNOWN INSTANCE NAME",
    }
    match service_name:
        case "iap.googleapis.com":
            # Name is not included in the event
            context |= {
                "id": deep_get(
                    event,
                    "resource",
                    "labels",
                    "instance_id",
                    default="UNKNOWN INSTANCE ID",
                )
            }
        case "oslogin.googleapis.com":
            context |= {
                "id": deep_get(
                    event, "labels", "instance_id", default="UNKNOWN INSTANCE ID"
                ),
                "name": deep_get(
                    event,
                    "protoPayload",
                    "request",
                    "instance",
                    default="UNKNOWN INSTANCE NAME",
                ),
            }
        case "compute.googleapis.com":
            if deep_get(event, "protoPayload", "methodName", default="").endswith(
                ".setCommonInstanceMetadata"
            ):
                # These events are targeted prokect-wide, so they don't have information about
                # specific instances.
                pass
            else:
                context |= {
                    # Will look like: projects/project-name/zones/zone-name/instances/instance-name
                    "name": deep_get(
                        event,
                        "protoPayload",
                        "resourceName",
                        default="/UNKNOWN INSTANCE NAME",
                    ).split("/")[-1],
                }

    if "serialport" in service_name:
        context |= {
            "id": deep_get(
                event,
                "resource",
                "labels",
                "instance_id",
                default="UNKNOWN INSTANCE ID",
            ),
            # Will look like:
            # projects/projectName/zones/zoneName/instances/instanceName/SerialPort/portNum
            "name": deep_get(
                event,
                "protoPayload",
                "resourceName",
                default="/UNKNOWN INSTANCE NAME//",
            ).split("/")[-3],
        }
    return context
