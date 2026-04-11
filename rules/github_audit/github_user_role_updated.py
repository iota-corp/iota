import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))


def rule(event):
    return event.get("action") == "org.update_member"


def title(event):
    return (
        f"Org owner [{event.get('actor')}] updated user's "
        f"[{event.get('user')}] role ('admin' or 'member')"
    )
