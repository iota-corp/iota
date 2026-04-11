#!/usr/bin/env python3

import json
import sys
import importlib.util
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any


class Rule:
    def __init__(self, path: Path):
        self.path = path
        self.rule_id = path.stem
        self.module = self._load_module()

    def _load_module(self):
        spec = importlib.util.spec_from_file_location(self.rule_id, self.path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def matches(self, event: Dict[str, Any]) -> bool:
        if not hasattr(self.module, "rule"):
            return False
        try:
            return bool(self.module.rule(event))
        except Exception:
            return False

    def get_title(self, event: Dict[str, Any]) -> str:
        if not hasattr(self.module, "title"):
            return self.rule_id
        try:
            return str(self.module.title(event))
        except Exception:
            return self.rule_id

    def get_severity(self, event: Dict[str, Any]) -> str:
        if not hasattr(self.module, "severity"):
            return "INFO"
        sev = self.module.severity
        try:
            return str(sev(event))
        except TypeError:
            try:
                return str(sev())
            except Exception:
                return "INFO"
        except Exception:
            return "INFO"

    def get_dedup(self, event: Dict[str, Any]) -> str:
        if not hasattr(self.module, "dedup"):
            return self.rule_id
        try:
            return str(self.module.dedup(event))
        except Exception:
            return self.rule_id


class Engine:
    def __init__(self, rules_dir: str):
        self.rules = self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str) -> List[Rule]:
        rules = []
        path = Path(rules_dir)
        for rule_file in path.rglob("*.py"):
            if rule_file.name.startswith("_"):
                continue
            try:
                rules.append(Rule(rule_file))
            except Exception:
                continue
        return rules

    def analyze(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        matches = []
        counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"match": 0, "no_match": 0}
        )
        for event in events:
            rule_event = self._unwrap_event(event)
            for rule in self.rules:
                if rule.matches(rule_event):
                    counts[rule.rule_id]["match"] += 1
                    matches.append(
                        {
                            "rule_id": rule.rule_id,
                            "title": rule.get_title(rule_event),
                            "severity": rule.get_severity(rule_event),
                            "dedup": rule.get_dedup(rule_event),
                            "event": event,
                        }
                    )
                else:
                    counts[rule.rule_id]["no_match"] += 1
        rule_evaluations = [
            {
                "rule_id": rid,
                "match": c["match"],
                "no_match": c["no_match"],
            }
            for rid, c in sorted(counts.items())
        ]
        return {"matches": matches, "rule_evaluations": rule_evaluations}

    def _unwrap_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event_source = event.get("eventSource", "")
        if event_source == "okta.com":
            return event.get("requestParameters", event)
        if event_source == "gsuite.google.com":
            return event.get("requestParameters", event)
        if event_source == "1password.com":
            return event.get("requestParameters", event)
        if event_source == "aws.bedrock.modelinvocation":
            return event.get("requestParameters", event)
        if event_source in ("github.com", "github.com.webhook"):
            return event.get("requestParameters", event)
        if event_source in (
            "cloudaudit.googleapis.com",
            "loadbalancing.googleapis.com",
        ):
            return event.get("requestParameters", event)
        if event_source == "eks.amazonaws.com":
            return event.get("requestParameters", event)
        if event_source in (
            "slack.com",
            "cloudflare.com.firewall",
            "cloudflare.com.http_request",
        ):
            return event.get("requestParameters", event)
        return event


def main():
    request = json.load(sys.stdin)
    rules_dir = request.get("rules_dir")
    events = request.get("events", [])

    engine = Engine(rules_dir)
    response = engine.analyze(events)
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    main()
