import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))

from github_helpers import github_alert_context

# The keys for MONITORED_ACTIONS are gh_org/repo_name
# The values for MONITORED_ACTIONS are a list of ["action_names"]
MONITORED_ACTIONS = {}


def rule(event):
    repo = event.get("repo", "")
    action_name = event.get("name", "")
    return all(
        [
            event.get("action", "") == "workflows.completed_workflow_run",
            event.get("conclusion", "") == "failure",
            repo in MONITORED_ACTIONS,
            action_name in MONITORED_ACTIONS.get(repo, []),
        ]
    )


def title(event):
    repo = event.get("repo", "<NO_REPO>")
    action_name = event.get("name", "<NO_ACTION_NAME>")
    return f"GitHub Action [{action_name}] in [{repo}] has failed"


def alert_context(event):
    a_c = github_alert_context(event)
    a_c["action"] = event.get("name", "<NO_ACTION_NAME>")
    a_c["action_run_link"] = (
        f"https://github.com/{a_c.get('repo')}/actions/"
        f"runs/{event.get('workflow_run_id', '<NO_RUN_ID>')}"
    )
    return a_c
