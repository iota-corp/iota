import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get

DESTRUCTIVE_STATEMENTS = [
    "UPDATE",
    "DELETE",
    "DROP_TABLE",
    "ALTER_TABLE",
    "TRUNCATE_TABLE",
]


def rule(event):
    if all(
        [
            deep_get(
                event, "resource", "type", default="<RESOURCE_NOT_FOUND>"
            ).startswith("bigquery"),
            deep_get(
                event,
                "protoPayload",
                "metadata",
                "jobChange",
                "job",
                "jobConfig",
                "type",
            )
            == "QUERY",
            deep_get(
                event,
                "protoPayload",
                "metadata",
                "jobChange",
                "job",
                "jobConfig",
                "queryConfig",
                "statementType",
                default="<STATEMENT_NOT_FOUND>",
            )
            in DESTRUCTIVE_STATEMENTS,
        ]
    ):
        return True

    if deep_get(event, "protoPayload", "metadata", "tableDeletion"):
        return True

    if deep_get(event, "protoPayload", "metadata", "datasetDeletion"):
        return True

    return False


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    statement = deep_get(
        event,
        "protoPayload",
        "metadata",
        "jobChange",
        "job",
        "jobConfig",
        "queryConfig",
        "statementType",
        default="<STATEMENT_NOT_FOUND>",
    )
    if (
        deep_get(
            event, "protoPayload", "metadata", "jobChange", "job", "jobConfig", "type"
        )
        == "QUERY"
    ):
        return f"GCP: [{actor}] performed a destructive BigQuery [{statement}] query"

    if deep_get(event, "protoPayload", "metadata", "tableDeletion"):
        return f"GCP: [{actor}] deleted a table in BigQuery"

    if deep_get(event, "protoPayload", "metadata", "datasetDeletion"):
        return f"GCP: [{actor}] deleted a dataset in BigQuery"

    # Default return value
    return f"GCP: [{actor}] performed a destructive BigQuery query"


def severity(event):
    statement = deep_get(
        event,
        "protoPayload",
        "metadata",
        "jobChange",
        "job",
        "jobConfig",
        "queryConfig",
        "statementType",
        default="<STATEMENT_NOT_FOUND>",
    )
    if statement in ("UPDATE", "DELETE"):
        return "INFO"
    return "DEFAULT"


def alert_context(event):
    return {
        "query": deep_get(
            event,
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "query",
            default="<QUERY_NOT_FOUND>",
        ),
        "actor": deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        ),
        "statement": deep_get(
            event,
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "statementType",
            default="<STATEMENT_NOT_FOUND>",
        ),
        "table": deep_get(
            event,
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "destinationTable",
        )
        or deep_get(
            event,
            "protoPayload",
            "metadata",
            "resourceName",
            default="<TABLE_NOT_FOUND>",
        ),
    }
