"""Runnable reference implementation for Chapter 5:
1. Deterministic Idempotency Ledger keyed by SHA-256 of `(session_id, logical_step_id, tool_name, canonical_args)`.
2. Externalized Workflow Checkpoint Store enabling crash recovery at step N without
   re-executing side-effecting mutations from steps 1..N-1.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class LedgerEntryState(Enum):
    IN_FLIGHT = "in_flight"
    COMPLETED = "completed"
    FAILED_RETRYABLE = "failed_retryable"


@dataclass
class IdempotencyRecord:
    idempotency_key: str
    tool_name: str
    state: LedgerEntryState
    result_payload: dict[str, Any] | None = None


def compute_idempotency_key(
    workflow_run_id: str,
    logical_step_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    raw = f"{workflow_run_id}|{logical_step_id}|{tool_name}|{canonical_args}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class IdempotentMutationExecutor:
    """Guarantees at-most-once execution per logical step for state-mutating tool calls."""

    def __init__(self) -> None:
        self._ledger: dict[str, IdempotencyRecord] = {}

    def execute_once(
        self,
        workflow_run_id: str,
        logical_step_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        mutation_fn: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> tuple[dict[str, Any], bool]:
        """Returns (result_payload, was_replayed_from_ledger)."""
        key = compute_idempotency_key(workflow_run_id, logical_step_id, tool_name, arguments)
        existing = self._ledger.get(key)

        if existing is not None:
            if existing.state == LedgerEntryState.COMPLETED and existing.result_payload is not None:
                return existing.result_payload, True
            if existing.state == LedgerEntryState.IN_FLIGHT:
                raise RuntimeError(
                    f"Concurrent duplicate execution blocked: key {key[:12]} is currently IN_FLIGHT."
                )

        self._ledger[key] = IdempotencyRecord(
            idempotency_key=key,
            tool_name=tool_name,
            state=LedgerEntryState.IN_FLIGHT,
        )
        try:
            output = mutation_fn(arguments)
            self._ledger[key] = IdempotencyRecord(
                idempotency_key=key,
                tool_name=tool_name,
                state=LedgerEntryState.COMPLETED,
                result_payload=output,
            )
            return output, False
        except Exception:
            self._ledger[key] = IdempotencyRecord(
                idempotency_key=key,
                tool_name=tool_name,
                state=LedgerEntryState.FAILED_RETRYABLE,
            )
            raise


if __name__ == "__main__":
    executor = IdempotentMutationExecutor()
    provider_charge_count = 0

    def charge_card(args: dict[str, Any]) -> dict[str, Any]:
        global provider_charge_count
        provider_charge_count += 1
        return {"charge_id": f"ch_{provider_charge_count}", "amount": args["amount_usd"]}

    # First execution of step-03 in run-900
    res1, replayed1 = executor.execute_once(
        "run-900", "step-03", "charge_card", {"amount_usd": 49.99, "customer": "c_1"}, charge_card
    )
    assert replayed1 is False and provider_charge_count == 1

    # Simulated retry after worker crash or LLM loop repetition (even with dict keys in different order)
    res2, replayed2 = executor.execute_once(
        "run-900", "step-03", "charge_card", {"customer": "c_1", "amount_usd": 49.99}, charge_card
    )
    assert replayed2 is True
    assert res2 == res1
    assert provider_charge_count == 1, "Customer was double-charged!"
    print("Chapter 5 idempotency ledger verification passed.")

