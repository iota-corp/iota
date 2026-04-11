import re

from iota_helpers import deep_get

BASH_INJECTION_PATTERNS = [
    r"\$\([^)]+\)",
    r"\$\{[^}]*\$\([^)]+\)[^}]*\}",
    r"\$\{[^}]*`[^`]+`[^}]*\}",
    r"<\([^)]+\)",
    r">\([^)]+\)",
    r"/bin/(?:sh|bash|dash|zsh)\s+-c\s+",
    r"(?:bash|sh)\s+-c\s+['\"]",
    r"\\x[0-9a-fA-F]{4,}",
    r"eval\s*\(\s*\$",
    r"exec\s*\(\s*\$",
    r"(?:curl|wget)\s+[^|>]+\|\s*(?:sh|bash)",
    r"nc\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+[0-9]+",
]

COMPILED_BASH_PATTERNS = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern in BASH_INJECTION_PATTERNS
]


def contains_bash_injection_pattern(text):
    if not text:
        return False
    return any(pattern.search(text) for pattern in COMPILED_BASH_PATTERNS)


def get_matched_bash_patterns(text):
    if not text:
        return []
    return [
        {
            "pattern": pattern.pattern,
            "match": pattern.findall(text),
        }
        for pattern in COMPILED_BASH_PATTERNS
        if pattern.search(text)
    ]


def actor_user(event):
    return event.get("actor")


def github_alert_context(event):
    actor = event.get("actor")
    if not actor:
        actor = deep_get(event, "sender", "login") or ""
    if isinstance(actor, dict):
        actor = actor.get("login") or actor.get("name") or ""
    return {
        "action": event.get("action", ""),
        "actor": actor,
        "actor_location": deep_get(event, "actor_location", "country_code"),
        "org": event.get("org", ""),
        "repo": event.get("repo", ""),
        "user": event.get("user", ""),
    }


def is_cross_fork_pr(event):
    head_repo = deep_get(event, "pull_request", "head", "repo", "full_name")
    base_repo = deep_get(event, "pull_request", "base", "repo", "full_name")

    if head_repo and base_repo:
        return head_repo != base_repo

    pull_requests = deep_get(event, "workflow_run", "pull_requests", default=[]) or []
    for pull_request in pull_requests:
        pr_head_repo = deep_get(pull_request, "head", "repo", "id")
        pr_base_repo = deep_get(pull_request, "base", "repo", "id")
        if pr_head_repo and pr_base_repo and pr_head_repo != pr_base_repo:
            return True

    head_repository = deep_get(event, "workflow_run", "head_repository")
    base_repository = deep_get(event, "workflow_run", "repository")

    if head_repository and base_repository:
        head_repo_id = head_repository.get("id")
        base_repo_id = base_repository.get("id")
        if head_repo_id and base_repo_id and head_repo_id != base_repo_id:
            return True

    return False


def is_pull_request_event(event):
    pr_actions = [
        "opened",
        "synchronize",
        "reopened",
        "closed",
        "assigned",
        "unassigned",
        "labeled",
        "unlabeled",
        "edited",
        "ready_for_review",
        "converted_to_draft",
    ]
    return event.get("action") in pr_actions and event.get("pull_request") is not None


def github_webhook_alert_context(event):
    context = github_alert_context(event)

    repository = event.get("repository", {})
    if isinstance(repository, dict):
        context["repository"] = {
            "name": repository.get("name"),
            "full_name": repository.get("full_name"),
            "private": repository.get("private"),
            "fork": repository.get("fork"),
            "default_branch": repository.get("default_branch"),
            "html_url": repository.get("html_url"),
        }

    sender = event.get("sender", {})
    if sender:
        context["sender"] = {
            "login": sender.get("login"),
            "id": sender.get("id"),
            "type": sender.get("type"),
            "html_url": sender.get("html_url"),
        }

    if is_pull_request_event(event):
        pull_request = event.get("pull_request", {})
        context["pull_request"] = {
            "number": pull_request.get("number"),
            "title": pull_request.get("title"),
            "state": pull_request.get("state"),
            "user": deep_get(pull_request, "user", "login"),
            "draft": pull_request.get("draft"),
            "html_url": pull_request.get("html_url"),
            "created_at": pull_request.get("created_at"),
            "updated_at": pull_request.get("updated_at"),
        }

        context["fork_analysis"] = {
            "is_cross_fork": is_cross_fork_pr(event),
            "head_repo": deep_get(pull_request, "head", "repo", "full_name"),
            "base_repo": deep_get(pull_request, "base", "repo", "full_name"),
            "head_ref": deep_get(pull_request, "head", "ref"),
            "base_ref": deep_get(pull_request, "base", "ref"),
            "head_sha": deep_get(pull_request, "head", "sha"),
            "base_sha": deep_get(pull_request, "base", "sha"),
        }

    pusher = event.get("pusher")
    if pusher:
        context["push_details"] = {
            "pusher": pusher,
            "ref": event.get("ref"),
            "before": event.get("before"),
            "after": event.get("after"),
            "forced": event.get("forced"),
            "size": len(event.get("commits", [])),
        }

        head_commit = event.get("head_commit", {})
        if head_commit:
            context["head_commit"] = {
                "id": head_commit.get("id"),
                "message": head_commit.get("message"),
                "author": head_commit.get("author", {}).get("name"),
                "committer": head_commit.get("committer", {}).get("name"),
                "timestamp": head_commit.get("timestamp"),
                "url": head_commit.get("url"),
            }

    return context


def github_reference_url(event):
    if is_pull_request_event(event):
        pr_url = deep_get(event, "pull_request", "html_url")
        if pr_url:
            return pr_url

    compare_url = event.get("compare")
    if compare_url:
        return compare_url

    workflow_run_url = deep_get(event, "workflow_run", "html_url")
    if workflow_run_url:
        return workflow_run_url

    repo_url = deep_get(event, "repository", "html_url")
    if repo_url:
        return repo_url

    return None
