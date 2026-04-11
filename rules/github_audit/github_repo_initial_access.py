import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))

from correlation_store import get_string_set, put_string_set

CODE_ACCESS_ACTIONS = [
    "git.clone",
    "git.push",
    "git.fetch",
]


def _actor_user(event):
    a = event.get("actor")
    if isinstance(a, dict):
        return a.get("login") or a.get("name") or ""
    return str(a or "")


def rule(event):
    allowed_users = ["secret-scanning[bot]"]
    actor = _actor_user(event)

    if not actor or any(allowed_user in actor for allowed_user in allowed_users):
        return False

    if event.get("action") in CODE_ACCESS_ACTIONS and not event.get(
        "repository_public"
    ):
        key = get_key(event)
        previous_access = get_string_set(key)
        if not previous_access:
            put_string_set(key, key)
            return True
    return False


def title(event):
    return (
        f"A user [{_actor_user(event)}] accessed a private repository "
        f"[{event.get('repo', '<UNKNOWN_REPO>')}] for the first time."
    )


def get_key(event):
    return __name__ + ":" + str(_actor_user(event)) + ":" + str(event.get("repo"))
