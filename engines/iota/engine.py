#!/usr/bin/env python3

import json
import struct
import sys
import importlib.util
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional

MAX_FRAME = 512 * 1024 * 1024


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


def read_frame(f) -> Optional[Dict[str, Any]]:
    hdr = f.read(4)
    if len(hdr) == 0:
        return None
    if len(hdr) < 4:
        raise EOFError("short frame header")
    (n,) = struct.unpack(">I", hdr)
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    body = f.read(n)
    if len(body) < n:
        raise EOFError("short frame body")
    return json.loads(body.decode("utf-8"))


def write_frame(f, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError("response too large")
    f.write(struct.pack(">I", len(data)))
    f.write(data)


class WorkerState:
    def __init__(self) -> None:
        self._engine: Optional[Engine] = None
        self._rules_dir: Optional[str] = None

    def get_engine(self, rules_dir: str) -> Engine:
        if self._rules_dir != rules_dir:
            self._engine = Engine(rules_dir)
            self._rules_dir = rules_dir
        assert self._engine is not None
        return self._engine


def worker_main() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    state = WorkerState()
    while True:
        try:
            req = read_frame(stdin)
        except EOFError:
            break
        if req is None:
            break
        rules_dir = req.get("rules_dir")
        events = req.get("events", [])
        if rules_dir is None:
            sys.stderr.write("engine worker: missing rules_dir\n")
            sys.exit(1)
        try:
            eng = state.get_engine(str(rules_dir))
            response = eng.analyze(events)
            write_frame(stdout, response)
            stdout.flush()
        except BrokenPipeError:
            break
        except Exception as e:
            sys.stderr.write(f"engine worker: analyze error: {e}\n")
            sys.exit(1)
    sys.exit(0)


def main():
    request = json.load(sys.stdin)
    rules_dir = request.get("rules_dir")
    events = request.get("events", [])

    engine = Engine(rules_dir)
    response = engine.analyze(events)
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "worker":
        worker_main()
    else:
        main()
