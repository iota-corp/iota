"""Unit tests for rule pack → log type indexing (run: python3 -m unittest discover -s engines/iota -p 'test_*.py')."""

import unittest
from pathlib import Path

from log_type_index import (
    applicable_log_types_for_pack,
    infer_log_type_from_event,
    pack_for_rule_file,
)


class TestPackForRuleFile(unittest.TestCase):
    def test_nested(self):
        root = "/tmp/rules"
        p = Path("/tmp/rules/github_audit/foo.py")
        self.assertEqual(pack_for_rule_file(root, p), "github_audit")

    def test_top_level_py(self):
        root = "/tmp/rules"
        p = Path("/tmp/rules/root_login.py")
        self.assertEqual(pack_for_rule_file(root, p), "")


class TestApplicableTypes(unittest.TestCase):
    def test_known_pack(self):
        self.assertEqual(
            applicable_log_types_for_pack("github_audit"),
            frozenset({"GitHub.Audit"}),
        )

    def test_unknown_pack(self):
        self.assertIsNone(applicable_log_types_for_pack("future_vendor"))

    def test_empty_pack(self):
        self.assertIsNone(applicable_log_types_for_pack(""))


class TestInferLogType(unittest.TestCase):
    def test_cloudtrail_default(self):
        self.assertEqual(
            infer_log_type_from_event(
                {"eventSource": "s3.amazonaws.com", "eventName": "GetObject"}
            ),
            "AWS.CloudTrail",
        )

    def test_okta(self):
        self.assertEqual(
            infer_log_type_from_event({"eventSource": "okta.com"}),
            "Okta.SystemLog",
        )

    def test_vpc_flow(self):
        self.assertEqual(
            infer_log_type_from_event(
                {
                    "eventSource": "vpcflowlogs.amazonaws.com",
                    "eventName": "VPCFlow",
                }
            ),
            "AWS.VPCFlow",
        )

    def test_alb(self):
        self.assertEqual(
            infer_log_type_from_event(
                {
                    "eventSource": "elasticloadbalancing.amazonaws.com",
                    "eventName": "ALB-GET",
                }
            ),
            "AWS.ALB",
        )


if __name__ == "__main__":
    unittest.main()
