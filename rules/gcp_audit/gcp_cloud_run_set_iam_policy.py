import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, deep_walk
from gcp_helpers import gcp_alert_context


def rule(event):
    if event.get("severity") == "ERROR":
        return False

    method_name = deep_get(event, "protoPayload", "methodName", default="")
    if not method_name.endswith("Services.SetIamPolicy"):
        return False

    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if (
            auth.get("permission") == "run.services.setIamPolicy"
            and auth.get("granted") is True
        ):
            return True
    return False


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    resource = deep_get(
        event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
    )
    service_name = resource.split("/")[-1] if "/" in resource else resource

    # Extract roles from the response bindings - there could be multiple
    bindings = deep_get(event, "protoPayload", "response", "bindings", default=[])

    # Handle multiple roles if present
    roles = []
    for binding in bindings:
        if binding.get("role"):
            roles.append(binding.get("role"))

    # Format roles for title
    if not roles:
        roles_str = "<NO_ROLES_FOUND>"
    elif len(roles) == 1:
        roles_str = roles[0]
    else:
        # If multiple roles, mention the count and list the first one
        roles_str = f"{len(roles)} roles including {roles[0]}"

    project_id = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )

    return (
        f"[GCP]: [{actor}] modified IAM policy for Cloud Run service [{service_name}] "
        f"with [{roles_str}] in project [{project_id}]"
    )


def alert_context(event):
    context = gcp_alert_context(event)

    # Extract the service name from the resource path for better context
    resource = deep_get(event, "protoPayload", "resourceName", default="")
    if resource:
        context["service_name"] = (
            resource.split("/")[-1] if "/" in resource else resource
        )

    # Get bindings and role information
    bindings = deep_get(event, "protoPayload", "response", "bindings", default=[])

    # Collect all roles and members
    all_roles = []
    all_members = []
    role_to_members = {}

    for binding in bindings:
        role = binding.get("role")
        members = binding.get("members", [])

        if role:
            all_roles.append(role)

        if members:
            all_members.extend(members)

            # Create mapping of role to members
            if role:
                role_to_members[role] = members

    # Store all collected information in the context
    context["assigned_roles"] = all_roles
    context["members_granted"] = all_members
    context["role_to_members_mapping"] = role_to_members

    return context
