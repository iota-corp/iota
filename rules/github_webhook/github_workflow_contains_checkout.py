import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    """Alert when a GitHub workflow job contains a checkout action step."""
    # Only check completed workflow jobs
    if event.get("action") != "completed":
        return False

    # Get the steps array from workflow_job
    steps = deep_get(event, "workflow_job", "steps", default=[])

    # Iterate through each step and check if the name contains "checkout" (case-insensitive)
    for step in steps:
        step_name = step.get("name", "").lower()
        if "checkout" in step_name:
            return True

    return False
