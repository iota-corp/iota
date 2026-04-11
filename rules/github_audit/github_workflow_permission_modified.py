import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))


def rule(event):
    return (
        event.get("action") == "org.set_default_workflow_permissions"
        and event.get("operation_type") == "modify"
    )


def title(event):
    return (
        f"Workflow permission settings for GITHUB_TOKENs have been changed"
        f" for your organization [{event.get('org')}]"
        f" by user [{event.get('actor')}]"
    )
