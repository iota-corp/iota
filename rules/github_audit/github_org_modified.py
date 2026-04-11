import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))


def rule(event):
    return (
        event.get("action") == "org.add_member"
        or event.get("action") == "org.remove_member"
    )


def title(event):
    action = event.get("action")
    if event.get("action") == "org.add_member":
        action = "added"
    elif event.get("action") == "org.remove_member":
        action = "removed"
    return (
        f"GitHub.Audit: User [{event.get('actor')}] {action} "
        f"{event.get('user', '<UNKNOWN_USER>')} to org [{event.get('org','<UNKNOWN_ORG>')}]"
    )
