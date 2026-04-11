import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))


def rule(event):
    return event.get("action") == "public_key.create"


def title(event):
    return f"User [{event.get('actor')}] created a new ssh key"
