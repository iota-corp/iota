import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))


def _output_body(event):
    out = event.get("output")
    if not isinstance(out, dict):
        return {}
    return out.get("outputBodyJSON") or out.get("outputBodyJson") or {}


def rule(event):
    if event.get("operation") not in ("InvokeModel", "Converse"):
        return False

    body = _output_body(event)
    stop_reason = body.get("stopReason")
    trace = body.get("amazon-bedrock-trace") or {}
    guard = trace.get("guardrail") if isinstance(trace.get("guardrail"), dict) else {}
    action_reason = guard.get("actionReason")

    if stop_reason == "guardrail_intervened":
        return True
    if isinstance(action_reason, str) and action_reason.startswith("Guardrail blocked"):
        return True
    return False


def title(event):
    model_id = event.get("modelId")
    operation_name = event.get("operation")
    account_id = event.get("accountId")
    body = _output_body(event)
    stop_reason = body.get("stopReason", "<UNKNOWN REASON>")
    trace = body.get("amazon-bedrock-trace") or {}
    guard = trace.get("guardrail") if isinstance(trace.get("guardrail"), dict) else {}
    action_reason = guard.get("actionReason", "<UNKNOWN ACTION REASON>")

    if action_reason == "<UNKNOWN ACTION REASON>":
        return (
            f"The model [{model_id}] was invoked with the operation [{operation_name}] "
            f"by the account [{account_id}]. Stop reason [{stop_reason}]."
        )
    if stop_reason == "<UNKNOWN REASON>":
        return (
            f"The model [{model_id}] was invoked with the operation [{operation_name}] "
            f"by the account [{account_id}]. Action reason [{action_reason}]."
        )
    return (
        f"The model [{model_id}] was invoked with the operation [{operation_name}] "
        f"by the account [{account_id}]. Stop reason [{stop_reason}]. "
        f"Action reason [{action_reason}]."
    )


def severity(event):
    return "INFO"
